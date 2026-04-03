package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// validZoneIDPattern matches Cloudflare Zone IDs (32 hex characters)
var validZoneIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// cloudflareZoneProvider is a custom DNS-01 challenge provider for Cloudflare
// that uses a user-specified Zone ID directly, bypassing lego's SOA-based zone detection.
// This fixes certificate issuance for domains under 2nd-level ccTLDs (e.g., .ai.kr, .pe.kr)
// where SOA queries return the registry zone instead of the user's zone.
type cloudflareZoneProvider struct {
	zoneID    string
	apiToken  string
	apiKey    string
	email     string
	mu        sync.Mutex
	recordIDs map[string]string
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type cfCreateRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newCloudflareZoneProvider(zoneID, apiToken, apiKey, email string) (*cloudflareZoneProvider, error) {
	if !validZoneIDPattern.MatchString(zoneID) {
		return nil, fmt.Errorf("invalid Cloudflare Zone ID format: must be 32 hex characters")
	}
	return &cloudflareZoneProvider{
		zoneID:    zoneID,
		apiToken:  apiToken,
		apiKey:    apiKey,
		email:     email,
		recordIDs: make(map[string]string),
	}, nil
}

func (p *cloudflareZoneProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	recordName := dns01.UnFqdn(info.EffectiveFQDN)

	// Create TXT record via Cloudflare API
	reqBody := cfCreateRequest{
		Type:    "TXT",
		Name:    recordName,
		Content: info.Value,
		TTL:     120,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("cloudflare: failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", p.zoneID)
	resp, err := p.doRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("cloudflare: failed to create TXT record: %w", err)
	}

	var record cfDNSRecord
	if err := json.Unmarshal(resp.Result, &record); err != nil {
		return fmt.Errorf("cloudflare: failed to parse create response: %w", err)
	}

	p.mu.Lock()
	p.recordIDs[token] = record.ID
	p.mu.Unlock()
	return nil
}

func (p *cloudflareZoneProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	recordID, ok := p.recordIDs[token]
	if !ok {
		p.mu.Unlock()
		return nil
	}
	delete(p.recordIDs, token)
	p.mu.Unlock()

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", p.zoneID, recordID)
	_, err := p.doRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("cloudflare: failed to delete TXT record: %w", err)
	}

	return nil
}

func (p *cloudflareZoneProvider) Timeout() (timeout, interval time.Duration) {
	return 180 * time.Second, 5 * time.Second
}

func (p *cloudflareZoneProvider) doRequest(method, url string, body io.Reader) (*cfAPIResponse, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if p.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiToken)
	} else {
		req.Header.Set("X-Auth-Email", p.email)
		req.Header.Set("X-Auth-Key", p.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp cfAPIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !apiResp.Success {
		if len(apiResp.Errors) > 0 {
			return nil, fmt.Errorf("API error: %s (code: %d)", apiResp.Errors[0].Message, apiResp.Errors[0].Code)
		}
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return &apiResp, nil
}
