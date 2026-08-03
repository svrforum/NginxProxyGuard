package service

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Platform-native message formatting (#221).
//
// The three channels are not interchangeable pipes. Discord renders embeds with
// a coloured bar; Telegram renders MarkdownV2; a webhook receiver wants JSON it
// can key off. Sending the same flat sentence to all three wastes what each can
// do and reads worst on the one people look at most.
//
// An operator template always wins: if somebody wrote a format, that is the
// message, and none of this applies.

// severityColour maps a severity to the bar colour Discord draws beside an
// embed. Values are the decimal form Discord expects, not a hex string.
func severityColour(severity string) int {
	switch severity {
	case "error":
		return 0xE5484D // red
	case "warning":
		return 0xF5A524 // amber
	default:
		return 0x30A46C // green
	}
}

// fieldOrder keeps a message's lines stable between sends. Map iteration order
// would otherwise reshuffle them and make two identical alerts look different.
var fieldOrder = []string{"host", "ip", "country", "count", "reason", "detail", "subject", "time"}

func orderedFields(fields map[string]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, k := range fieldOrder {
		if v := fields[k]; v != "" {
			out = append(out, k)
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(fields))
	for k, v := range fields {
		if !seen[k] && v != "" && k != "event" {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// headline is the one-line summary every format leads with.
func headline(lang string, msg model.RenderedMessage) string {
	sev := "info"
	if msg.Severity == "error" || msg.Severity == "warning" {
		sev = msg.Severity
	}
	return tr(lang, "severity."+sev) + " — " + eventTitle(lang, msg.Event)
}

// eventTitle turns a key into something readable in the channel's language.
func eventTitle(lang, key string) string {
	if v, ok := notificationStrings[normaliseLang(lang)]["event."+key]; ok && v != "" {
		return v
	}
	if v, ok := notificationStrings[LangEnglish]["event."+key]; ok && v != "" {
		return v
	}
	return strings.ReplaceAll(key, ".", " ")
}

// fieldLabel names a field in the channel's language. Unknown keys fall through
// to the key itself, which is still more use than blank.
func fieldLabel(lang, key string) string {
	if v, ok := notificationStrings[normaliseLang(lang)]["field."+key]; ok && v != "" {
		return v
	}
	if v, ok := notificationStrings[LangEnglish]["field."+key]; ok && v != "" {
		return v
	}
	return key
}

// discordEmbed builds the embed body. Falls back to plain content when the
// channel asked for plain text or the operator supplied a template.
func discordEmbed(lang string, msg model.RenderedMessage) map[string]any {
	fields := []map[string]any{}
	for _, k := range orderedFields(msg.Fields) {
		if k == "time" || k == "detail" {
			continue // time is the embed timestamp; detail is the description
		}
		fields = append(fields, map[string]any{
			"name":   fieldLabel(lang, k),
			"value":  truncateRunes(msg.Fields[k], 1024),
			"inline": true,
		})
		if len(fields) == 25 { // Discord's per-embed field cap
			break
		}
	}

	description := msg.Fields["detail"]
	if description == "" {
		description = msg.Text
	}

	embed := map[string]any{
		"title":       truncateRunes(headline(lang, msg), 256),
		"description": truncateRunes(description, 4096),
		"color":       severityColour(msg.Severity),
		"footer":      map[string]any{"text": tr(lang, "footer.signature")},
	}
	if !msg.At.IsZero() {
		embed["timestamp"] = msg.At.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if len(fields) > 0 {
		embed["fields"] = fields
	}
	return embed
}

// telegramMarkdown builds a MarkdownV2 body.
//
// Escaping happens per value and the markup is added afterwards. Escaping the
// finished string would escape the asterisks and backticks too, and the message
// would arrive with the markup showing.
func telegramMarkdown(lang string, msg model.RenderedMessage) string {
	var b strings.Builder
	icon := map[string]string{"error": "🔴", "warning": "🟠"}[msg.Severity]
	if icon == "" {
		icon = "🟢"
	}
	fmt.Fprintf(&b, "%s *%s*", icon, escapeMarkdownV2(headline(lang, msg)))

	if d := msg.Fields["detail"]; d != "" {
		fmt.Fprintf(&b, "\n%s", escapeMarkdownV2(d))
	}
	for _, k := range orderedFields(msg.Fields) {
		if k == "detail" {
			continue
		}
		fmt.Fprintf(&b, "\n%s: `%s`", escapeMarkdownV2(fieldLabel(lang, k)), escapeMarkdownV2(msg.Fields[k]))
	}
	return b.String()
}

// plainText is the fallback every channel can carry.
func plainText(lang string, msg model.RenderedMessage) string {
	var b strings.Builder
	b.WriteString(headline(lang, msg))
	if d := msg.Fields["detail"]; d != "" {
		b.WriteString("\n" + d)
	}
	for _, k := range orderedFields(msg.Fields) {
		if k == "detail" {
			continue
		}
		fmt.Fprintf(&b, "\n%s: %s", fieldLabel(lang, k), msg.Fields[k])
	}
	return b.String()
}

// usesTemplate reports whether the operator has taken over formatting.
func usesTemplate(ch *model.NotificationChannel) bool {
	return strings.TrimSpace(ch.Template) != ""
}

// SampleMessage builds a realistic example of one event, so the operator can
// press Test on a specific alert and see exactly what will arrive — including
// how their template renders and how their channel formats it.
//
// The values are documentation-range addresses and example.com hostnames on
// purpose: a sample must never carry real traffic data off the box.
func SampleMessage(lang, eventKey string) model.RenderedMessage {
	now := time.Now()
	if eventKey == "" || !model.IsKnownEvent(eventKey) {
		eventKey = "test"
	}

	fields := map[string]string{
		"event":    eventKey,
		"time":     now.Format(time.RFC3339),
		"instance": "npg",
	}
	severity := "info"

	switch eventKey {
	case "cert.renewal_failed":
		severity = "error"
		fields["host"] = "app.example.com"
		fields["detail"] = tr(lang, "sample.certFail")
		fields["subject"] = "app.example.com"
	case "cert.renewed":
		fields["host"] = "app.example.com"
		fields["detail"] = tr(lang, "sample.certOK")
	case "ddns.sync_failed":
		severity = "error"
		fields["host"] = "home.example.com"
		fields["detail"] = tr(lang, "sample.ddnsFail")
	case "ddns.recovered":
		fields["host"] = "home.example.com"
		fields["ip"] = "203.0.113.42"
	case "backup.failed":
		severity = "error"
		fields["subject"] = "scheduled"
		fields["detail"] = tr(lang, "sample.backup")
	case "nginx.reload_failed":
		severity = "error"
		fields["subject"] = "nginx"
		fields["detail"] = tr(lang, "sample.nginx")
	case "auth.login_failed":
		severity = "warning"
		fields["subject"] = "admin"
		fields["ip"] = "198.51.100.7"
		fields["count"] = "5"
		fields["reason"] = "locked_out"
	case "ip.banned":
		severity = "warning"
		fields["ip"] = "192.0.2.5"
		fields["host"] = "app.example.com"
		fields["count"] = "3"
		fields["reason"] = "fail2ban"
		fields["subject"] = "192.0.2.5 " + tr(lang, "sample.andMore")
	case "sso.login_refused":
		severity = "warning"
		fields["subject"] = "google"
		fields["count"] = "2"
		fields["reason"] = "not_on_allowlist"
	default:
		fields["detail"] = tr(lang, "sample.test")
	}

	msg := model.RenderedMessage{
		Event: eventKey, Severity: severity, Fields: fields, At: now,
	}
	msg.Text = plainText(lang, msg)
	return msg
}
