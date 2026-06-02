package service

import (
	"context"
	"encoding/json"
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

func (u *duckDNSUpdater) Update(ctx context.Context, rec model.DDNSRecord, rawCreds json.RawMessage, ip string) error {
	var c model.DuckDNSCredentials
	if err := json.Unmarshal(rawCreds, &c); err != nil {
		return fmt.Errorf("duckdns: bad credentials: %w", err)
	}
	url := buildDuckDNSURL(u.base, rec.Hostname, c.Token, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if strings.TrimSpace(string(b)) != "OK" {
		return fmt.Errorf("duckdns update failed: %s", strings.TrimSpace(string(b)))
	}
	return nil
}
