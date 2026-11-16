package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Infomaniak's DynDNS endpoint updates an existing hostname using dedicated
// DynDNS credentials. It does not create/delete records or manage ACME TXT records.
type infomaniakUpdater struct {
	client   *http.Client
	endpoint string
}

func newInfomaniakUpdater() *infomaniakUpdater {
	return &infomaniakUpdater{
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		endpoint: "https://infomaniak.com/nic/update",
	}
}

func (u *infomaniakUpdater) Update(ctx context.Context, rec model.DDNSRecord, rawCreds json.RawMessage, ip string) error {
	var c model.InfomaniakCredentials
	if json.Unmarshal(rawCreds, &c) != nil {
		return fmt.Errorf("%w: infomaniak credentials are not valid JSON", model.ErrInvalidCredentials)
	}
	if err := c.Validate(); err != nil {
		return err
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() {
		return fmt.Errorf("%w: infomaniak DDNS requires IPv4", model.ErrInvalidInput)
	}
	q := url.Values{"hostname": {rec.Hostname}, "myip": {ip}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("infomaniak: cannot build update request")
	}
	// Keep credentials out of URLs, errors and persisted DDNS status.
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("User-Agent", "NginxProxyGuard")
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("infomaniak: update request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if err != nil {
		return fmt.Errorf("infomaniak: cannot read update response")
	}
	if len(raw) > 1024 {
		return fmt.Errorf("infomaniak: oversized update response")
	}
	body := strings.TrimSpace(string(raw))
	// Infomaniak reports these protocol errors with HTTP 400; some DynDNS
	// implementations also use 200. Never mistake outages for bad credentials.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
		switch body {
		case "badauth":
			return fmt.Errorf("%w: infomaniak rejected the DynDNS username or password", model.ErrInvalidCredentials)
		case "nohost":
			return fmt.Errorf("%w: infomaniak hostname is not configured for these DynDNS credentials", model.ErrInvalidInput)
		}
	}
	if resp.StatusCode != http.StatusOK {
		return ddnsStatusError(resp.StatusCode, "infomaniak: update failed (HTTP %d)", resp.StatusCode)
	}
	fields := strings.Fields(body)
	if len(fields) == 2 {
		switch fields[0] {
		case "successfully_changed", "no_change", "good", "nochg":
			received, err := netip.ParseAddr(fields[1])
			if err == nil && received == address {
				return nil
			}
			return fmt.Errorf("infomaniak: response IP does not match the requested IPv4 address")
		}
	}
	// Do not echo arbitrary remote content: it could contain credentials.
	return fmt.Errorf("infomaniak: unexpected update response")
}
