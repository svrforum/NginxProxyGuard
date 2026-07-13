package service

import "testing"

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
