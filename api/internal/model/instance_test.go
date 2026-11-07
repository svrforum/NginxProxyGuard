package model

import (
	"strings"
	"testing"
)

func TestNormalizeInstanceName(t *testing.T) {
	ok := map[string]string{
		"  home lab  ":          "home lab",
		"":                      "",
		strings.Repeat("가", 32): strings.Repeat("가", 32),
	}
	for in, want := range ok {
		if got, err := NormalizeInstanceName(in); err != nil || got != want {
			t.Errorf("NormalizeInstanceName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{strings.Repeat("a", 33), "line\nbreak", "tab\there"} {
		if _, err := NormalizeInstanceName(in); err == nil {
			t.Errorf("NormalizeInstanceName(%q) accepted", in)
		}
	}
}
