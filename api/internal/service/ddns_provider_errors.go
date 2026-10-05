package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// ddnsRejection classifies the HTTP status of a DDNS provider's answer. A
// status the operator can act on returns the sentinel that the sync handler
// answers 400 for (#312): 401/403 means the stored credentials were refused,
// and any other 4xx means the provider rejected what it was asked to do — a
// zone, domain or record the account does not have. 408, 429 and 5xx are a
// slow exchange or the provider's own trouble and return nil, so they stay
// plain errors and a 500, the same as failing to reach the provider at all:
// an outage must never be reported to the operator as "your credentials are
// wrong".
func ddnsRejection(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return model.ErrInvalidCredentials
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests:
		return nil
	case status >= 400 && status < 500:
		return model.ErrInvalidInput
	default:
		return nil
	}
}

// ddnsStatusError builds the error for a provider answer that was not a
// success. When ddnsRejection classifies the status the sentinel is wrapped,
// so errors.Is sees it; the message itself is kept as it was, behind the
// sentinel's prefix.
func ddnsStatusError(status int, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if kind := ddnsRejection(status); kind != nil {
		return fmt.Errorf("%w: %s", kind, msg)
	}
	return errors.New(msg)
}

// redactDDNSSecret removes secret, as written and as it appears in a query
// string, from err's text. A provider that takes its secret in the request URL
// (DuckDNS) has it quoted back by anything that quotes the request: a page that
// echoes it, or net/http's own wording for a bad redirect or a malformed
// answer. That text becomes the API response, ddns_records.last_error, the
// ddns.sync_failed notification and the log, so it is matched by value, which
// covers every such wording rather than the ones known today (#312). The
// sentinel the sync handler answers 400 for still matches through errors.Is;
// the rest of the chain is dropped, since its text is what is being hidden.
func redactDDNSSecret(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	msg := err.Error()
	redacted := strings.NewReplacer(secret, "[redacted]", url.QueryEscape(secret), "[redacted]").Replace(msg)
	if redacted == msg {
		return err
	}
	var kind error
	for _, sentinel := range []error{model.ErrInvalidCredentials, model.ErrInvalidInput} {
		if errors.Is(err, sentinel) {
			kind = sentinel
			break
		}
	}
	return &ddnsRedactedError{msg: redacted, kind: kind}
}

// ddnsRedactedError is an error whose text had a secret removed. It unwraps
// only to the sentinel the original carried, never to the original itself.
type ddnsRedactedError struct {
	msg  string
	kind error
}

func (e *ddnsRedactedError) Error() string { return e.msg }

func (e *ddnsRedactedError) Unwrap() error { return e.kind }
