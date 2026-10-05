package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

type duckDNSUpdater struct {
	client *http.Client
	base   string // default https://www.duckdns.org
}

func newDuckDNSUpdater() *duckDNSUpdater {
	return &duckDNSUpdater{client: &http.Client{Timeout: 15 * time.Second}, base: "https://www.duckdns.org"}
}

// buildDuckDNSURL builds the DuckDNS update URL. DuckDNS expects the bare
// subdomain (the label before ".duckdns.org"), not the full hostname.
func buildDuckDNSURL(base, hostname, token, ip string) string {
	sub := strings.TrimSuffix(hostname, ".duckdns.org")
	q := url.Values{"domains": {sub}, "token": {token}, "ip": {ip}}
	return fmt.Sprintf("%s/update?%s", base, q.Encode())
}

// duckDNSRequestError reports an update request that got no answer, without
// the request URL. DuckDNS takes the token in the query string, and net/http
// renders a failed request as `Get "<full URL>": <cause>` (*url.Error), token
// included. That text is the API response, ddns_records.last_error (shown to
// anyone who can read DDNS records), the ddns.sync_failed notification and the
// log line, so only the endpoint and the underlying cause are kept.
func duckDNSRequestError(endpoint string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return fmt.Errorf("duckdns: update request to %s failed: %w", endpoint, err)
}

func (u *duckDNSUpdater) Update(ctx context.Context, rec model.DDNSRecord, rawCreds json.RawMessage, ip string) (err error) {
	var c model.DuckDNSCredentials
	if err := json.Unmarshal(rawCreds, &c); err != nil {
		return fmt.Errorf("duckdns: bad credentials: %w", err)
	}
	// The token is in the request URL, so whatever quotes the request quotes
	// the token: an echoed body, or net/http's wording for a bad redirect or a
	// malformed answer. Every error from here on is redacted by value.
	defer func() { err = redactDDNSSecret(err, c.Token) }()
	url := buildDuckDNSURL(u.base, rec.Hostname, c.Token, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return duckDNSRequestError(u.base, err)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return duckDNSRequestError(u.base, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// DuckDNS answers OK/KO with a 200, so a page with another status came
		// from whatever sits in front of it — a WAF, a proxy, a load balancer.
		// That says nothing about the token or the subdomain, so it stays a
		// plain error (500), whatever the status. Its body is not echoed: an
		// error page that reflects the request line would carry the token.
		return fmt.Errorf("duckdns update failed: HTTP %d", resp.StatusCode)
	}
	switch body := strings.TrimSpace(string(b)); body {
	case "OK":
		return nil
	case "KO":
		// DuckDNS's one refusal, and it gives no reason: the token is wrong, or
		// the subdomain is not on that token's account. Either way the stored
		// configuration is the operator's to fix, not a server fault (#312).
		return fmt.Errorf("%w: duckdns update failed: KO — DuckDNS rejected the token, or the subdomain is not on that token's account", model.ErrInvalidCredentials)
	default:
		// Anything else is not an answer DuckDNS gives, so nothing says the
		// credentials are at fault; it stays a plain error. The body is kept
		// for the operator; a token it echoes is redacted on the way out.
		return fmt.Errorf("duckdns update failed: %s", body)
	}
}
