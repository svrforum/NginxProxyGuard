package service

import (
	"context"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// Every subscribable event needs a title in both languages; eventTitle would
// otherwise print "disk space_low" to a Korean channel.
func TestEveryCatalogueEventHasATitle(t *testing.T) {
	for _, e := range model.EventCatalogue {
		for _, lang := range []string{LangEnglish, LangKorean} {
			if v, ok := notificationStrings[lang]["event."+e.Key]; !ok || v == "" {
				t.Errorf("%s has no %s title", e.Key, lang)
			}
		}
	}
}

// A disk at 85% is a notice, not a red "Problem"; the existing failure keys
// keep "error".
func TestTransitionSeverityFollowsCatalogue(t *testing.T) {
	store := newFakeStore("disk.space_low", "backup.failed")
	s := NewNotificationServiceWithStore(store)
	ctx := context.Background()
	_ = s.EmitTransition(ctx, "disk.space_low", "db", true, "", nil)
	_ = s.EmitTransition(ctx, "backup.failed", "scheduled", true, "boom", nil)
	if store.enqueued[0].Severity != "warning" || store.enqueued[1].Severity != "error" {
		t.Fatalf("severities = %s, %s", store.enqueued[0].Severity, store.enqueued[1].Severity)
	}
}

// Critical recovers silently; the one recovery message is disk.space_recovered.
func TestCriticalDiskRecoveryIsSilent(t *testing.T) {
	store := newFakeStore("disk.space_low", "disk.space_critical", "disk.space_recovered")
	s := NewNotificationServiceWithStore(store)
	ctx := context.Background()
	_ = s.EmitTransition(ctx, "disk.space_critical", "db", true, "", nil)
	_ = s.EmitTransition(ctx, "disk.space_critical", "db", false, "", nil)
	if len(store.enqueued) != 1 {
		t.Fatalf("got %d messages, want only the critical one", len(store.enqueued))
	}
	if got, _ := store.GetState(ctx, "disk.space_critical", "db"); got != stateOK {
		t.Fatalf("state = %q, want ok", got)
	}
	_ = s.EmitTransition(ctx, "disk.space_low", "db", true, "", nil)
	_ = s.EmitTransition(ctx, "disk.space_low", "db", false, "", nil)
	if got := store.enqueued[len(store.enqueued)-1]; got.Event != "disk.space_recovered" || got.Severity != "resolved" {
		t.Fatalf("low recovered as %s/%s", got.Event, got.Severity)
	}
}

func TestResolveQuietlySendsNothing(t *testing.T) {
	store := newFakeStore("disk.space_low", "disk.space_recovered")
	s := NewNotificationServiceWithStore(store)
	ctx := context.Background()
	_ = s.EmitTransition(ctx, "disk.space_low", "backups", true, "", nil)
	if err := s.ResolveQuietly(ctx, "disk.space_low", "backups"); err != nil {
		t.Fatal(err)
	}
	if len(store.enqueued) != 1 {
		t.Fatalf("ResolveQuietly sent a message: %v", diskEvents(store))
	}
	if got, _ := store.GetState(ctx, "disk.space_low", "backups"); got != stateOK {
		t.Fatalf("state = %q, want ok", got)
	}
}

// Roles travel as codes (a webhook keys off them) and are translated for
// people.
func TestDiskCodesAreTranslatedForPeopleOnly(t *testing.T) {
	msg := SampleMessage(LangKorean, "disk.space_critical")
	text := plainText(LangKorean, msg)
	for _, want := range []string{"디스크 공간 위험", "데이터베이스", "nginx 로그", "여유 공간", "저장 내용"} {
		if !strings.Contains(text, want) {
			t.Errorf("ko text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "nginx_logs") {
		t.Errorf("a code leaked into the ko text:\n%s", text)
	}
	if msg.Fields["roles"] != "db,nginx_logs,backups,docker" {
		t.Errorf("fields must keep the codes: %#v", msg.Fields)
	}
	tg := telegramMarkdown(LangEnglish, msg)
	if !strings.Contains(tg, "nginx logs") {
		t.Errorf("telegram lacks translated roles:\n%s", tg)
	}
	emb := discordEmbed(LangEnglish, msg)
	found := false
	for _, f := range emb["fields"].([]map[string]any) {
		if f["value"] == "database, nginx logs, backups, Docker images and container logs" {
			found = true
		}
	}
	if !found {
		t.Errorf("discord embed lacks translated roles: %#v", emb["fields"])
	}
	// An unknown code passes through rather than vanishing.
	if got := displayValueIn(LangKorean, "roles", "db,new_role"); got != "데이터베이스, new_role" {
		t.Errorf("displayValueIn = %q", got)
	}
}

func TestDiskSamplesLeakNoKeys(t *testing.T) {
	for _, key := range []string{"disk.space_low", "disk.space_critical", "disk.space_recovered"} {
		for _, lang := range []string{LangEnglish, LangKorean} {
			text := plainText(lang, SampleMessage(lang, key))
			for _, leak := range []string{"field.", "value.", "event.", "severity."} {
				if strings.Contains(text, leak) {
					t.Errorf("%s/%s leaked %q:\n%s", lang, key, leak, text)
				}
			}
		}
	}
	if SampleMessage(LangEnglish, "disk.space_recovered").Severity != "resolved" {
		t.Error("the recovered sample must carry the resolved glyph")
	}
	if SampleMessage(LangEnglish, "disk.space_low").Severity != "warning" {
		t.Error("the low sample must carry the warning glyph, as the real alert does")
	}
}

// Disk fields pass the allowlist; nothing else rides along.
func TestDiskFieldsAreAllowlisted(t *testing.T) {
	store := newFakeStore("disk.space_low")
	s := NewNotificationServiceWithStore(store)
	_ = s.EmitTransition(context.Background(), "disk.space_low", "db", true, "86.0% · 1 GB / 2 GB", map[string]string{
		"subject": "npg-db:/var/lib/postgresql/data", "free": "1 GB", "growth_per_day": "+0.1 GB",
		"days_to_full": "10", "roles": "db", "raw_log": "SECRET",
	})
	f := store.enqueued[0].Fields
	for _, k := range []string{"free", "growth_per_day", "days_to_full", "roles", "detail", "subject"} {
		if f[k] == "" {
			t.Errorf("%s was dropped: %#v", k, f)
		}
	}
	if _, leaked := f["raw_log"]; leaked {
		t.Error("raw_log passed the allowlist")
	}
}
