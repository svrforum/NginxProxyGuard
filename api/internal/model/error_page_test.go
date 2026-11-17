package model

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateCustomErrorPageHTML(t *testing.T) {
	if err := ValidateCustomErrorPageHTML("<h1>Down for maintenance</h1>"); err != nil {
		t.Fatalf("valid page refused: %v", err)
	}
	for name, html := range map[string]string{
		"empty":     "  \n",
		"too large": strings.Repeat("a", customErrorPageMaxBytes+1),
		"NUL":       "<p>\x00</p>",
		"not UTF-8": "<p>\xff</p>",
	} {
		if err := ValidateCustomErrorPageHTML(html); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: got %v, want an invalid-input error", name, err)
		}
	}
	for _, code := range []int{403, 502, 503, 504} {
		if !IsCustomErrorPageStatus(code) {
			t.Errorf("%d should be replaceable", code)
		}
	}
	for _, code := range []int{0, 401, 404, 500} {
		if IsCustomErrorPageStatus(code) {
			t.Errorf("%d should not be replaceable", code)
		}
	}
}
