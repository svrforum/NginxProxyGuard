package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

var cfZoneIDRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

type cloudflareUpdater struct {
	client  *http.Client
	apiBase string // default https://api.cloudflare.com/client/v4
}

func newCloudflareUpdater() *cloudflareUpdater {
	return &cloudflareUpdater{client: &http.Client{Timeout: 15 * time.Second}, apiBase: "https://api.cloudflare.com/client/v4"}
}

type cfResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// cloudflareARecordBody builds the JSON body for create/update of an A record.
func cloudflareARecordBody(name, ip string, proxied bool, ttl int) []byte {
	if ttl <= 0 {
		ttl = 1
	}
	b, _ := json.Marshal(map[string]interface{}{
		"type": "A", "name": name, "content": ip, "proxied": proxied, "ttl": ttl,
	})
	return b
}

func (u *cloudflareUpdater) authHeader(req *http.Request, c model.CloudflareCredentials) {
	if c.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIToken)
	} else {
		req.Header.Set("X-Auth-Email", c.Email)
		req.Header.Set("X-Auth-Key", c.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")
}

func (u *cloudflareUpdater) do(ctx context.Context, method, url string, c model.CloudflareCredentials, body []byte) (*cfResp, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	u.authHeader(req, c)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var cr cfResp
	if err := json.Unmarshal(raw, &cr); err != nil {
		return nil, fmt.Errorf("cloudflare: bad response (%d): %s", resp.StatusCode, string(raw))
	}
	if !cr.Success {
		msg := "unknown error"
		if len(cr.Errors) > 0 {
			msg = cr.Errors[0].Message
		}
		return nil, fmt.Errorf("cloudflare API error: %s", msg)
	}
	return &cr, nil
}

func (u *cloudflareUpdater) resolveZoneID(ctx context.Context, c model.CloudflareCredentials, hostname string) (string, error) {
	if cfZoneIDRe.MatchString(c.ZoneID) {
		return c.ZoneID, nil
	}
	// Fallback: guess the zone as the last two labels (covers the common case).
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("cloudflare: cannot derive zone for %q; set Zone ID in DNS provider", hostname)
	}
	guess := strings.Join(labels[len(labels)-2:], ".")
	cr, err := u.do(ctx, http.MethodGet, fmt.Sprintf("%s/zones?name=%s", u.apiBase, guess), c, nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(cr.Result, &zones); err != nil || len(zones) == 0 {
		return "", fmt.Errorf("cloudflare: zone %q not found; set Zone ID in DNS provider", guess)
	}
	return zones[0].ID, nil
}

func (u *cloudflareUpdater) Update(ctx context.Context, rec model.DDNSRecord, rawCreds json.RawMessage, ip string) error {
	var c model.CloudflareCredentials
	if err := json.Unmarshal(rawCreds, &c); err != nil {
		return fmt.Errorf("cloudflare: bad credentials: %w", err)
	}
	zone, err := u.resolveZoneID(ctx, c, rec.Hostname)
	if err != nil {
		return err
	}

	// find existing A record by name
	listURL := fmt.Sprintf("%s/zones/%s/dns_records?type=A&name=%s", u.apiBase, zone, rec.Hostname)
	cr, err := u.do(ctx, http.MethodGet, listURL, c, nil)
	if err != nil {
		return err
	}
	var recs []struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	_ = json.Unmarshal(cr.Result, &recs)

	body := cloudflareARecordBody(rec.Hostname, ip, rec.Proxied, rec.TTL)
	if len(recs) > 0 {
		if recs[0].Content == ip {
			return nil // already correct
		}
		_, err = u.do(ctx, http.MethodPut, fmt.Sprintf("%s/zones/%s/dns_records/%s", u.apiBase, zone, recs[0].ID), c, body)
		return err
	}
	_, err = u.do(ctx, http.MethodPost, fmt.Sprintf("%s/zones/%s/dns_records", u.apiBase, zone), c, body)
	return err
}
