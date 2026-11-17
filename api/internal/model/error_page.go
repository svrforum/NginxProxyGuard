package model

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// CustomErrorPage is HTML an operator sets for one of NPG's own error pages
// (#335): the block page (403) and the backend error pages (502, 503, 504).
// It replaces the built-in page on every proxy host and the default server.
// nginx serves it with scripts blocked (CSP sandbox): the page appears on
// every proxied site's own origin, so a script in it would run with that
// site's cookies.
type CustomErrorPage struct {
	StatusCode int       `json:"status_code"`
	HTML       string    `json:"html"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CustomErrorPageStatuses are the pages that can be replaced.
var CustomErrorPageStatuses = []int{403, 502, 503, 504}

// customErrorPageMaxBytes bounds a page; nginx reads it from disk per error.
const customErrorPageMaxBytes = 256 * 1024

// IsCustomErrorPageStatus reports whether code is a page that can be replaced.
func IsCustomErrorPageStatus(code int) bool {
	for _, c := range CustomErrorPageStatuses {
		if c == code {
			return true
		}
	}
	return false
}

// ValidateCustomErrorPageHTML checks the HTML of a custom page.
func ValidateCustomErrorPageHTML(html string) error {
	if strings.TrimSpace(html) == "" {
		return fmt.Errorf("%w: html is required; reset the page to go back to the built-in one", ErrInvalidInput)
	}
	if len(html) > customErrorPageMaxBytes {
		return fmt.Errorf("%w: html must be at most %d KB", ErrInvalidInput, customErrorPageMaxBytes/1024)
	}
	if !utf8.ValidString(html) || strings.ContainsRune(html, 0) {
		return fmt.Errorf("%w: html must be UTF-8 text without NUL characters", ErrInvalidInput)
	}
	return nil
}
