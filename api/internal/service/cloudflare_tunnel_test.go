package service

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestValidateTunnelToken(t *testing.T) {
	valid := "eyJhIjoiYWJjIiwidCI6ImRlZiIsInMiOiJnaGkifQ=="
	if err := ValidateTunnelToken(valid); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	for name, tok := range map[string]string{
		"empty":        "",
		"newline":      "abc\ndef",
		"semicolon":    "abc;def",
		"space":        "abc def",
		"control":      "abc\x00def",
		"too-long":     string(make([]byte, 5000)),
		"shell-braces": "abc{def}",
	} {
		if err := ValidateTunnelToken(tok); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// fakeTunnelNginx records token-file operations for syncFile tests.
type fakeTunnelNginx struct {
	written string
	removed bool
}

func (f *fakeTunnelNginx) WriteCloudflaredToken(token string) error { f.written = token; return nil }
func (f *fakeTunnelNginx) RemoveCloudflaredToken() error            { f.removed = true; return nil }
func (f *fakeTunnelNginx) CloudflaredReady(_ context.Context) (int, error) {
	return 0, nil
}
func (f *fakeTunnelNginx) GetHTTPSPort() string { return "443" }
func (f *fakeTunnelNginx) GetHTTPPort() string  { return "80" }

// TestSyncFileRejectsInvalidStoredToken: a token that entered the DB without
// validation (e.g. backup import) must never reach the supervisor-consumed
// file — syncFile removes the file instead of writing it.
func TestSyncFileRejectsInvalidStoredToken(t *testing.T) {
	f := &fakeTunnelNginx{}
	s := NewCloudflareTunnelService(nil, f)
	if err := s.syncFile(&model.CloudflareTunnel{Enabled: true, Token: "abc;rm -rf /\n"}); err != nil {
		t.Fatalf("syncFile: %v", err)
	}
	if f.written != "" {
		t.Errorf("invalid stored token was written to file: %q", f.written)
	}
	if !f.removed {
		t.Error("expected token file removal for invalid stored token")
	}
}
