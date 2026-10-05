package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// ddnsErrKind names the sentinel an updater error carries. "credentials" and
// "input" are what the sync handler answers 400 for; "" stays a 500.
func ddnsErrKind(err error) string {
	switch {
	case errors.Is(err, model.ErrInvalidCredentials):
		return "credentials"
	case errors.Is(err, model.ErrInvalidInput):
		return "input"
	default:
		return ""
	}
}

// Only a 4xx other than 408 and 429 is the operator's to fix. A timeout, a
// rate limit or a provider fault must not reach them as "your credentials are
// wrong". (#312)
func TestDDNSStatusErrorClassifiesProviderStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "credentials"},
		{http.StatusForbidden, "credentials"},
		{http.StatusBadRequest, "input"},
		{http.StatusNotFound, "input"},
		{http.StatusConflict, "input"},
		{http.StatusRequestTimeout, ""},
		{http.StatusTooManyRequests, ""},
		{http.StatusInternalServerError, ""},
		{http.StatusBadGateway, ""},
		{http.StatusServiceUnavailable, ""},
		{http.StatusFound, ""},
	}
	for _, tc := range cases {
		err := ddnsStatusError(tc.status, "provider said no (%d)", tc.status)
		if got := ddnsErrKind(err); got != tc.want {
			t.Errorf("HTTP %d: kind = %q, want %q (%v)", tc.status, got, tc.want, err)
		}
		if want := fmt.Sprintf("provider said no (%d)", tc.status); !strings.Contains(err.Error(), want) {
			t.Errorf("HTTP %d: message %q lost %q", tc.status, err, want)
		}
	}
}

// The secret is matched by value, as written and as a query string carries it,
// and the sentinel the sync handler answers 400 for survives. The redacted
// error never unwraps to the text it hides, and an error that does not contain
// the secret is returned as it was. (#312)
func TestRedactDDNSSecret(t *testing.T) {
	const secret = "tok en/1+2" // a query string escapes it differently
	escaped := url.QueryEscape(secret)

	err := redactDDNSSecret(fmt.Errorf("%w: echoed %s and %s", model.ErrInvalidCredentials, secret, escaped), secret)
	if want := "invalid credentials: echoed [redacted] and [redacted]"; err.Error() != want {
		t.Errorf("got %q, want %q", err, want)
	}
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Errorf("sentinel lost: %v", err)
	}

	inner := errors.New("echoed " + secret)
	if errors.Is(redactDDNSSecret(inner, secret), inner) {
		t.Error("the redacted error still unwraps to the text it hides")
	}

	plain := errors.New("nothing to hide")
	if got := redactDDNSSecret(plain, secret); got != plain {
		t.Errorf("an error without the secret was replaced: %v", got)
	}
	if got := redactDDNSSecret(plain, ""); got != plain {
		t.Errorf("an empty secret changed the error: %v", got)
	}
}
