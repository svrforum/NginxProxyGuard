package service

import (
	"errors"
	"strings"
	"testing"
)

func TestValidMaxMindAccountID(t *testing.T) {
	cases := map[string]bool{
		"123456": true,
		" 42 ":   true, // trimmed
		"":        false,
		"0":       false, // placeholder default — invalid
		"-5":      false,
		"abc":     false,
		"12ab":    false,
	}
	for in, want := range cases {
		if got := ValidMaxMindAccountID(in); got != want {
			t.Errorf("ValidMaxMindAccountID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestExtractGeoIPUpdateError(t *testing.T) {
	// Real-ish geoipupdate -v output: version banner first, real error later.
	out := "geoipupdate version 7.0.1 (0df3abc)\n" +
		"2026/06/17 Performing get of GeoLite2-Country\n" +
		"error retrieving updates: error while getting database for GeoLite2-Country: unexpected HTTP status code: received: 401 Unauthorized: Invalid account ID or license key\n"
	got := ExtractGeoIPUpdateError(out, errors.New("exit status 1"))
	if strings.HasPrefix(got, "geoipupdate version") {
		t.Fatalf("must NOT surface the version banner; got %q", got)
	}
	if !strings.Contains(got, "401 Unauthorized") {
		t.Fatalf("must surface the real error line; got %q", got)
	}

	// No usable output → fall back to the exit error.
	if got := ExtractGeoIPUpdateError("geoipupdate version 7.0.1 (x)\n", errors.New("exit status 2")); got != "exit status 2" {
		t.Fatalf("banner-only output should fall back to exit error; got %q", got)
	}
}
