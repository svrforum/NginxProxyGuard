package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// dynuUpdater syncs a managed DDNS record to Dynu via its REST API v2
// (https://api.dynu.com/v2) using the API-Key header. Credentials carry only an
// API key (model.DynuCredentials); the domain is resolved from the hostname, so
// the flow is: GET /dns (list domains) -> match -> POST /dns/{id} {name, ipv4Address}.
type dynuUpdater struct {
	client  *http.Client
	apiBase string // default https://api.dynu.com/v2
}

func newDynuUpdater() *dynuUpdater {
	return &dynuUpdater{client: &http.Client{Timeout: 15 * time.Second}, apiBase: "https://api.dynu.com/v2"}
}

type dynuDomain struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (u *dynuUpdater) do(ctx context.Context, method, url, apiKey string, body []byte) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("API-Key", apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

// matchDynuDomain returns the account domain whose name equals the hostname, or
// (subdomain case) the longest domain name that is a suffix of the hostname.
func matchDynuDomain(domains []dynuDomain, hostname string) (dynuDomain, bool) {
	var best dynuDomain
	found := false
	for _, d := range domains {
		if d.Name == hostname {
			return d, true
		}
		if strings.HasSuffix(hostname, "."+d.Name) && len(d.Name) > len(best.Name) {
			best = d
			found = true
		}
	}
	return best, found
}

func (u *dynuUpdater) Update(ctx context.Context, rec model.DDNSRecord, rawCreds json.RawMessage, ip string) error {
	var c model.DynuCredentials
	if err := json.Unmarshal(rawCreds, &c); err != nil {
		return fmt.Errorf("dynu: bad credentials: %w", err)
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("dynu: missing api_key")
	}

	// 1. List the account's domains and match one to this hostname.
	raw, code, err := u.do(ctx, http.MethodGet, u.apiBase+"/dns", c.APIKey, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("dynu: list domains failed (%d): %s", code, strings.TrimSpace(string(raw)))
	}
	var list struct {
		Domains []dynuDomain `json:"domains"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("dynu: bad domains response: %s", strings.TrimSpace(string(raw)))
	}
	dom, ok := matchDynuDomain(list.Domains, rec.Hostname)
	if !ok {
		return fmt.Errorf("dynu: no domain in this Dynu account matches %q", rec.Hostname)
	}

	// 2. Update the domain's IPv4 address (Dynu's DDNS-managed A record).
	body, _ := json.Marshal(map[string]interface{}{"name": dom.Name, "ipv4Address": ip})
	raw, code, err = u.do(ctx, http.MethodPost, fmt.Sprintf("%s/dns/%d", u.apiBase, dom.ID), c.APIKey, body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("dynu: update failed (%d): %s", code, strings.TrimSpace(string(raw)))
	}
	return nil
}
