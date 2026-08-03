package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Discord and Telegram adapters (#221).
//
// Both providers punish naive clients, in different ways, and both quirks below
// come from their current documentation rather than from guesswork.

const (
	// discordContentLimit is the maximum length of a webhook message.
	discordContentLimit = 2000
	// telegramTextLimit is the maximum length of a sendMessage text.
	telegramTextLimit = 4096
	telegramAPIBase   = "https://api.telegram.org"
)

// truncateRunes cuts to a rune count, not a byte count. Cutting a multi-byte
// character in half produces a body both APIs reject as malformed, and Korean
// or emoji in a hostname is entirely ordinary.
func truncateRunes(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit])
}

// ── Discord ───────────────────────────────────────────────────────────────

type discordAdapter struct{ client *http.Client }

func newDiscordAdapter() *discordAdapter {
	return &discordAdapter{client: notifyHTTPClient()}
}

func (a *discordAdapter) Send(ctx context.Context, ch *model.NotificationChannel, msg model.RenderedMessage) (Outcome, time.Duration, error) {
	target := ch.Config["url"]
	if err := model.ValidateNotificationTarget(target, ch.AllowPrivateTarget); err != nil {
		return OutcomeFailed, 0, err
	}

	// A template means the operator took over formatting; otherwise a rich
	// channel gets an embed with a severity-coloured bar, which is the whole
	// reason to treat Discord as Discord rather than as a pipe.
	var payload any
	if ch.RichFormat && !usesTemplate(ch) {
		payload = map[string]any{"embeds": []any{discordEmbed(msg)}}
	} else {
		text := msg.Text
		if !usesTemplate(ch) {
			text = plainText(msg)
		}
		payload = map[string]string{"content": truncateRunes(text, discordContentLimit)}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return OutcomeFailed, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return OutcomeFailed, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NginxProxyGuard")

	resp, err := a.client.Do(req)
	if err != nil {
		return OutcomeRetry, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	// classifyResponse already treats 404 as terminal, which is what Discord
	// requires: it documents that repeatedly posting to a deleted webhook
	// "will result in a temporary restriction". 429s are counted toward a limit
	// of 10,000 invalid requests per 10 minutes enforced by a Cloudflare IP
	// ban, so Retry-After is obeyed rather than approximated.
	outcome, wait := classifyResponse(resp.StatusCode, resp.Header.Get("Retry-After"))
	if outcome == OutcomeSent {
		return outcome, 0, nil
	}
	return outcome, wait, fmt.Errorf("discord returned %d", resp.StatusCode)
}

// ── Telegram ──────────────────────────────────────────────────────────────

// chatIDPersister is how the adapter reports a migrated chat id without knowing
// about the repository.
type chatIDPersister func(ctx context.Context, channelID, newChatID string)

type telegramAdapter struct {
	client  *http.Client
	base    string
	persist chatIDPersister
}

func newTelegramAdapter(persist chatIDPersister) *telegramAdapter {
	return newTelegramAdapterWithBase(telegramAPIBase, persist)
}

func newTelegramAdapterWithBase(base string, persist chatIDPersister) *telegramAdapter {
	return &telegramAdapter{client: notifyHTTPClient(), base: strings.TrimRight(base, "/"), persist: persist}
}

// markdownV2Escapes is the exact set Telegram requires escaping in MarkdownV2.
// Missing one means the API answers 400 for any message containing it — and
// since '.' and '-' are in the set, that would be every hostname, IP address,
// timestamp and UUID NPG ever sends.
const markdownV2Escapes = "_*[]()~`>#+-=|{}.!"

func escapeMarkdownV2(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, r := range s {
		if strings.ContainsRune(markdownV2Escapes, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Parameters  struct {
		MigrateToChatID int64 `json:"migrate_to_chat_id"`
		RetryAfter      int   `json:"retry_after"`
	} `json:"parameters"`
}

func (a *telegramAdapter) Send(ctx context.Context, ch *model.NotificationChannel, msg model.RenderedMessage) (Outcome, time.Duration, error) {
	token := ch.Config["bot_token"]
	chatID := ch.Config["chat_id"]
	if token == "" || chatID == "" {
		return OutcomeFailed, 0, fmt.Errorf("telegram channel is missing its bot token or chat id")
	}

	// Escape first, then truncate: escaping adds backslashes and could push an
	// otherwise-legal message past the limit.
	var text string
	if ch.RichFormat && !usesTemplate(ch) {
		text = telegramMarkdown(msg)
	} else {
		body := msg.Text
		if !usesTemplate(ch) {
			body = plainText(msg)
		}
		text = escapeMarkdownV2(body)
	}
	text = truncateRunes(text, telegramTextLimit)
	body, err := json.Marshal(map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "MarkdownV2",
	})
	if err != nil {
		return OutcomeFailed, 0, err
	}

	endpoint := a.base + "/bot" + url.PathEscape(token) + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return OutcomeFailed, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NginxProxyGuard")

	resp, err := a.client.Do(req)
	if err != nil {
		return OutcomeRetry, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var parsed telegramResponse
	_ = json.Unmarshal(raw, &parsed)

	// A group upgraded to a supergroup answers with a new id. Persisting it and
	// retrying is the difference between a channel that survives the upgrade and
	// one that fails forever against an id that no longer exists.
	//
	// Control flow keys off the presence of this parameter, never off parsing
	// the description — Telegram documents that error_code contents "are
	// subject to change in the future".
	if parsed.Parameters.MigrateToChatID != 0 {
		newID := strconv.FormatInt(parsed.Parameters.MigrateToChatID, 10)
		if a.persist != nil {
			a.persist(ctx, ch.ID, newID)
		}
		ch.Config["chat_id"] = newID
		return OutcomeRetry, time.Second, fmt.Errorf("chat migrated to %s", newID)
	}

	// Telegram reports throttling in parameters.retry_after as well as in the
	// header, and the documented ceiling is 20 messages a minute to a group —
	// which is exactly where home-server operators point notifications.
	if parsed.Parameters.RetryAfter > 0 {
		return OutcomeRetry, time.Duration(parsed.Parameters.RetryAfter) * time.Second,
			fmt.Errorf("telegram throttled for %ds", parsed.Parameters.RetryAfter)
	}

	outcome, wait := classifyResponse(resp.StatusCode, resp.Header.Get("Retry-After"))
	if outcome == OutcomeSent && parsed.OK {
		return OutcomeSent, 0, nil
	}
	if outcome == OutcomeSent {
		// 200 with ok=false is possible; treat it as terminal so a permanently
		// malformed message does not cycle.
		return OutcomeFailed, 0, fmt.Errorf("telegram refused: %s", parsed.Description)
	}
	detail := parsed.Description
	if detail == "" {
		detail = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return outcome, wait, fmt.Errorf("telegram: %s", detail)
}

// TelegramChat is one conversation a bot can currently reach.
type TelegramChat struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Type  string `json:"type"`
}

// DetectTelegramChats asks getUpdates which conversations the bot has seen.
//
// This exists because a Telegram bot cannot start a conversation — the operator
// must message it or add it to a group first — and the chat id is not shown
// anywhere in the Telegram UI. Telling somebody to "find your chat id" without
// giving them a way to find it is where a setup guide stops being a guide.
func DetectTelegramChats(ctx context.Context, botToken string) ([]TelegramChat, error) {
	return detectTelegramChatsAt(ctx, telegramAPIBase, botToken)
}

func detectTelegramChatsAt(ctx context.Context, base, botToken string) ([]TelegramChat, error) {
	if strings.TrimSpace(botToken) == "" {
		return nil, fmt.Errorf("invalid bot_token: required")
	}
	endpoint := strings.TrimRight(base, "/") + "/bot" + url.PathEscape(botToken) + "/getUpdates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := notifyHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach Telegram: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var parsed struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      []struct {
			Message struct {
				Chat struct {
					ID        int64  `json:"id"`
					Title     string `json:"title"`
					Username  string `json:"username"`
					FirstName string `json:"first_name"`
					Type      string `json:"type"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("Telegram returned something unexpected")
	}
	if !parsed.OK {
		detail := parsed.Description
		if detail == "" {
			detail = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("Telegram refused: %s", detail)
	}

	seen := map[int64]bool{}
	out := []TelegramChat{}
	for _, u := range parsed.Result {
		c := u.Message.Chat
		if c.ID == 0 || seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		title := c.Title
		if title == "" {
			title = strings.TrimSpace(c.FirstName + " " + c.Username)
		}
		out = append(out, TelegramChat{ID: strconv.FormatInt(c.ID, 10), Title: title, Type: c.Type})
	}
	return out, nil
}
