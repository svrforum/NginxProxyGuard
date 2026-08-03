package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// NotificationHandler exposes the channel registry and the delivery log. (#221)
type NotificationHandler struct {
	repo       *repository.NotificationRepository
	dispatcher *service.NotificationDispatcher
	audit      *service.AuditService
}

func NewNotificationHandler(repo *repository.NotificationRepository, d *service.NotificationDispatcher, audit *service.AuditService) *NotificationHandler {
	return &NotificationHandler{repo: repo, dispatcher: d, audit: audit}
}

// secretKeysFor names the config entries that are credentials and must never be
// read back. A Discord webhook URL is itself the credential — anyone holding it
// can post to the channel — so it is masked exactly like a bot token.
func secretKeysFor(channelType string) []string {
	switch channelType {
	case model.NotificationTypeDiscord:
		return []string{"url"}
	case model.NotificationTypeTelegram:
		return []string{"bot_token"}
	default:
		// A generic webhook URL often carries a token in its path, and any
		// header_* entry is an authorization value by definition.
		return []string{"url"}
	}
}

func maskChannel(c *model.NotificationChannel) {
	for _, k := range secretKeysFor(c.Type) {
		if c.Config[k] != "" {
			c.Config[k] = model.SecretPlaceholder
		}
	}
	for k := range c.Config {
		if strings.HasPrefix(k, "header_") && c.Config[k] != "" {
			c.Config[k] = model.SecretPlaceholder
		}
	}
}

func (h *NotificationHandler) List(c echo.Context) error {
	ctx := c.Request().Context()
	if !h.repo.TablesExist(ctx) {
		return c.JSON(http.StatusOK, map[string]any{"data": []model.NotificationChannel{}})
	}
	channels, err := h.repo.List(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to list channels"})
	}
	for i := range channels {
		maskChannel(&channels[i])
	}
	return c.JSON(http.StatusOK, map[string]any{
		"data":   channels,
		"events": model.EventCatalogue,
	})
}

func (h *NotificationHandler) Create(c echo.Context) error {
	ctx := c.Request().Context()
	if !h.repo.TablesExist(ctx) {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "Notification tables are missing — check the migration log"})
	}
	var req model.CreateNotificationChannelRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	if err := req.Validate(true); err != nil {
		return classifyNotificationError(c, err)
	}
	id, err := h.repo.Create(ctx, &req)
	if err != nil {
		return classifyNotificationError(c, err)
	}
	created, err := h.repo.GetByID(ctx, id)
	if err != nil || created == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Created but could not be read back"})
	}
	maskChannel(created)
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(ctx, c),
			"notification_channel_created", map[string]any{"name": created.Name, "type": created.Type})
	}
	return c.JSON(http.StatusCreated, created)
}

func (h *NotificationHandler) Update(c echo.Context) error {
	ctx := c.Request().Context()
	id := c.Param("id")
	existing, err := h.repo.GetByID(ctx, id)
	if err != nil {
		return classifyNotificationError(c, err)
	}
	if existing == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Channel not found"})
	}

	var req model.UpdateNotificationChannelRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	// The UI round-trips the mask; a masked value means "keep what is stored".
	// Without this, editing an unrelated field would blank the credential.
	if req.Config == nil {
		req.Config = map[string]string{}
	}
	for k, v := range req.Config {
		if v == model.SecretPlaceholder {
			req.Config[k] = existing.Config[k]
		}
	}
	if err := req.Validate(false); err != nil {
		return classifyNotificationError(c, err)
	}
	if err := h.repo.Update(ctx, id, &req); err != nil {
		return classifyNotificationError(c, err)
	}
	updated, err := h.repo.GetByID(ctx, id)
	if err != nil || updated == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Updated but could not be read back"})
	}
	maskChannel(updated)
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(ctx, c),
			"notification_channel_updated", map[string]any{"name": updated.Name, "type": updated.Type})
	}
	return c.JSON(http.StatusOK, updated)
}

func (h *NotificationHandler) Delete(c echo.Context) error {
	ctx := c.Request().Context()
	if err := h.repo.Delete(ctx, c.Param("id")); err != nil {
		return classifyNotificationError(c, err)
	}
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(ctx, c),
			"notification_channel_deleted", map[string]any{"id": c.Param("id")})
	}
	return c.NoContent(http.StatusNoContent)
}

// Test delivers immediately rather than queueing, so the button reports a real
// result instead of "accepted".
func (h *NotificationHandler) Test(c echo.Context) error {
	ctx := c.Request().Context()
	ch, err := h.repo.GetByID(ctx, c.Param("id"))
	if err != nil {
		return classifyNotificationError(c, err)
	}
	if ch == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Channel not found"})
	}
	var req struct {
		Event string `json:"event"`
	}
	_ = c.Bind(&req) // an empty body means the generic test
	if err := h.dispatcher.SendTest(ctx, ch, req.Event); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "sent"})
}

// Deliveries answers "why did I not get an alert".
func (h *NotificationHandler) Deliveries(c echo.Context) error {
	ctx := c.Request().Context()
	if !h.repo.TablesExist(ctx) {
		return c.JSON(http.StatusOK, map[string]any{"data": []model.OutboxEntry{}})
	}
	entries, err := h.repo.RecentDeliveries(ctx, c.Param("id"), 50)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to list deliveries"})
	}
	return c.JSON(http.StatusOK, map[string]any{"data": entries})
}

// DetectTelegramChats answers "what is my chat id", which Telegram shows
// nowhere in its own interface. Without it the setup instruction would be
// "find your chat id" with no way to find it.
func (h *NotificationHandler) DetectTelegramChats(c echo.Context) error {
	var req struct {
		BotToken  string `json:"bot_token"`
		ChannelID string `json:"channel_id"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	// The UI sends the mask when editing a saved channel rather than the real
	// token, so the stored one is used.
	if (req.BotToken == "" || req.BotToken == model.SecretPlaceholder) && req.ChannelID != "" {
		if ch, err := h.repo.GetByID(c.Request().Context(), req.ChannelID); err == nil && ch != nil {
			req.BotToken = ch.Config["bot_token"]
		}
	}
	chats, err := service.DetectTelegramChats(c.Request().Context(), req.BotToken)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]any{"data": chats})
}

func classifyNotificationError(c echo.Context, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Channel not found"})
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "already exists"):
		return c.JSON(http.StatusConflict, map[string]string{"error": msg})
	case strings.HasPrefix(msg, "invalid"):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Operation failed"})
}
