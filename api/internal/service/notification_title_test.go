package service

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A backup's recovery travels under the failure's own key, so the headline used
// to read "✅ Resolved — scheduled backup failed" — a sentence that contradicts
// itself.
func TestRecoveryHeadlineDoesNotContradictItself(t *testing.T) {
	for _, key := range []string{"backup.failed", "nginx.reload_failed"} {
		msg := model.RenderedMessage{Event: key, Severity: "resolved", Fields: map[string]string{}}
		for _, lang := range []string{"en", "ko"} {
			h := headline(lang, msg)
			if strings.Contains(h, "failed") || strings.Contains(h, "실패") {
				t.Errorf("%s/%s recovery headline still says failed: %q", lang, key, h)
			}
			if !strings.Contains(h, "✅") {
				t.Errorf("%s/%s lost its resolved glyph: %q", lang, key, h)
			}
		}
	}
	// A failure keeps its own title.
	fail := model.RenderedMessage{Event: "backup.failed", Severity: "error", Fields: map[string]string{}}
	if !strings.Contains(headline("ko", fail), "실패") {
		t.Errorf("the failure headline lost its wording: %q", headline("ko", fail))
	}
	// An event with a distinct recovery key is unaffected.
	ok := model.RenderedMessage{Event: "cert.renewed", Severity: "resolved", Fields: map[string]string{}}
	if !strings.Contains(headline("ko", ok), "인증서 갱신 성공") {
		t.Errorf("cert recovery changed: %q", headline("ko", ok))
	}
}
