package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// ── Discord ───────────────────────────────────────────────────────────────

func TestDiscordAdapterPostsContent(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(204) // Discord's success status for a webhook post
	}))
	defer srv.Close()

	// Plain mode: one content string, no embed.
	ch := &model.NotificationChannel{
		Type: model.NotificationTypeDiscord, AllowPrivateTarget: true, RichFormat: false,
		Config: map[string]string{"url": srv.URL},
	}
	out, _, err := newDiscordAdapter().Send(context.Background(), ch,
		model.RenderedMessage{Event: "ip.banned", Severity: "warning",
			Fields: map[string]string{"ip": "192.0.2.5"}})
	if err != nil || out != OutcomeSent {
		t.Fatalf("out=%v err=%v", out, err)
	}
	content, _ := got["content"].(string)
	if !strings.Contains(content, "addresses banned") || !strings.Contains(content, "192.0.2.5") {
		t.Fatalf("content = %q", content)
	}
	if _, hasEmbed := got["embeds"]; hasEmbed {
		t.Fatal("plain mode should not send an embed")
	}
}

// Rich mode is what makes Discord look like Discord rather than a pipe: a
// severity-coloured bar, a title, and the fields as columns.
func TestDiscordRichModeSendsAnEmbed(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ch := &model.NotificationChannel{
		Type: model.NotificationTypeDiscord, AllowPrivateTarget: true, RichFormat: true,
		Config: map[string]string{"url": srv.URL},
	}
	_, _, err := newDiscordAdapter().Send(context.Background(), ch,
		model.RenderedMessage{Event: "cert.renewal_failed", Severity: "error",
			Fields: map[string]string{"host": "a.example.com", "detail": "dns timeout"}})
	if err != nil {
		t.Fatal(err)
	}
	embeds, _ := got["embeds"].([]any)
	if len(embeds) != 1 {
		t.Fatalf("embeds = %#v", got)
	}
	e, _ := embeds[0].(map[string]any)
	if !strings.Contains(e["title"].(string), "certificate renewal failed") {
		t.Fatalf("title = %v", e["title"])
	}
	if e["description"] != "dns timeout" {
		t.Fatalf("description = %v", e["description"])
	}
	// Red for an error — the colour is the fastest thing to read in a busy channel.
	if int(e["color"].(float64)) != 0xE5484D {
		t.Fatalf("color = %v", e["color"])
	}
	fields, _ := e["fields"].([]any)
	if len(fields) == 0 {
		t.Fatal("host should appear as a field")
	}
}

// A template means the operator took over; rich formatting must step aside.
func TestTemplateBeatsRichFormat(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	ch := &model.NotificationChannel{
		Type: model.NotificationTypeDiscord, AllowPrivateTarget: true, RichFormat: true,
		Template: "custom", Config: map[string]string{"url": srv.URL},
	}
	_, _, _ = newDiscordAdapter().Send(context.Background(), ch,
		model.RenderedMessage{Event: "x", Text: "my own wording"})
	if got["content"] != "my own wording" {
		t.Fatalf("body = %#v", got)
	}
}

// Discord documents that repeatedly posting to a deleted webhook "will result
// in a temporary restriction", so a 404 must be terminal.
func TestDiscordDeletedWebhookIsTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	ch := &model.NotificationChannel{
		Type: model.NotificationTypeDiscord, AllowPrivateTarget: true,
		Config: map[string]string{"url": srv.URL},
	}
	out, _, _ := newDiscordAdapter().Send(context.Background(), ch, model.RenderedMessage{Text: "x"})
	if out != OutcomeFailed {
		t.Fatalf("out = %v, want failed", out)
	}
}

func TestDiscordHonoursRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	ch := &model.NotificationChannel{
		Type: model.NotificationTypeDiscord, AllowPrivateTarget: true,
		Config: map[string]string{"url": srv.URL},
	}
	out, wait, _ := newDiscordAdapter().Send(context.Background(), ch, model.RenderedMessage{Text: "x"})
	if out != OutcomeRetry || wait != 3*time.Second {
		t.Fatalf("out=%v wait=%v", out, wait)
	}
}

func TestDiscordTruncatesToTheLimit(t *testing.T) {
	long := strings.Repeat("a", 3000)
	if got := truncateRunes(long, discordContentLimit); len([]rune(got)) != discordContentLimit {
		t.Fatalf("len = %d, want %d", len([]rune(got)), discordContentLimit)
	}
	// Truncation must be rune-safe: cutting a multi-byte character in half
	// produces a body Discord rejects as malformed.
	multi := strings.Repeat("가", 3000)
	got := truncateRunes(multi, discordContentLimit)
	if !json.Valid([]byte(`"` + got + `"`)) {
		t.Fatal("truncation produced invalid UTF-8")
	}
}

// ── Telegram ──────────────────────────────────────────────────────────────

// Telegram's MarkdownV2 requires escaping 18 characters. Miss one and the API
// answers 400 for any message containing it — which for '.' and '-' means every
// hostname, IP address, timestamp and UUID NPG would ever send.
func TestEscapeMarkdownV2CoversAllEighteen(t *testing.T) {
	const required = "_*[]()~`>#+-=|{}.!"
	if len([]rune(required)) != 18 {
		t.Fatalf("the required set has %d characters, expected 18", len([]rune(required)))
	}
	got := escapeMarkdownV2(required)
	for _, r := range required {
		if !strings.Contains(got, `\`+string(r)) {
			t.Errorf("%q was not escaped: %q", r, got)
		}
	}
}

func TestEscapeMarkdownV2OnRealValues(t *testing.T) {
	for _, s := range []string{"a.example.com", "192.0.2.5", "2026-08-03T09:00:00Z", "cert.renewal_failed"} {
		if escaped := escapeMarkdownV2(s); !strings.Contains(escaped, `\`) {
			t.Errorf("%q produced no escaping: %q", s, escaped)
		}
	}
}

func TestTelegramSendsEscapedText(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	ch := &model.NotificationChannel{
		Type:   model.NotificationTypeTelegram,
		Config: map[string]string{"bot_token": "1:x", "chat_id": "-100"},
	}
	a := newTelegramAdapterWithBase(srv.URL, nil)
	out, _, err := a.Send(context.Background(), ch, model.RenderedMessage{
		Event: "host.down", Severity: "error",
		Fields: map[string]string{"host": "a.example.com"}})
	if err != nil || out != OutcomeSent {
		t.Fatalf("out=%v err=%v", out, err)
	}
	if got["chat_id"] != "-100" {
		t.Fatalf("chat_id = %#v", got["chat_id"])
	}
	text, _ := got["text"].(string)
	if !strings.Contains(text, `a\.example\.com`) {
		t.Fatalf("text was not escaped: %q", text)
	}
}

// A group upgraded to a supergroup answers with migrate_to_chat_id. Without
// persisting it the channel fails forever on an id that no longer exists.
func TestTelegramChatIDMigration(t *testing.T) {
	var migrated string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,` +
			`"description":"Bad Request: group chat was upgraded to a supergroup chat",` +
			`"parameters":{"migrate_to_chat_id":-1001234567890}}`))
	}))
	defer srv.Close()

	ch := &model.NotificationChannel{
		ID: "ch-1", Type: model.NotificationTypeTelegram,
		Config: map[string]string{"bot_token": "1:x", "chat_id": "-100"},
	}
	a := newTelegramAdapterWithBase(srv.URL, func(_ context.Context, channelID, chatID string) {
		migrated = chatID
	})
	out, _, _ := a.Send(context.Background(), ch, model.RenderedMessage{Text: "hi"})
	if migrated != "-1001234567890" {
		t.Fatalf("new chat id not persisted, got %q", migrated)
	}
	if out != OutcomeRetry {
		t.Fatalf("out = %v, want retry so the message lands on the new id", out)
	}
}

// Telegram documents that error_code contents "are subject to change", so
// control flow keys off the HTTP status and the presence of the migration
// parameter, never on parsing the description.
func TestTelegramPlain400IsTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()
	ch := &model.NotificationChannel{
		Type:   model.NotificationTypeTelegram,
		Config: map[string]string{"bot_token": "1:x", "chat_id": "-100"},
	}
	out, _, _ := newTelegramAdapterWithBase(srv.URL, nil).Send(context.Background(), ch, model.RenderedMessage{Text: "x"})
	if out != OutcomeFailed {
		t.Fatalf("out = %v, want failed", out)
	}
}

func TestTelegramTruncates(t *testing.T) {
	long := strings.Repeat("a", 5000)
	if got := truncateRunes(long, telegramTextLimit); len([]rune(got)) != telegramTextLimit {
		t.Fatalf("len = %d, want %d", len([]rune(got)), telegramTextLimit)
	}
}
