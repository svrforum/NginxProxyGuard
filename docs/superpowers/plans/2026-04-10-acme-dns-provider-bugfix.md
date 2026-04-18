# ACME DNS Provider Bugfix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 6 bugs in the ACME DNS-01 challenge code that cause Cloudflare certificate issuance failures and race conditions.

**Architecture:** Replace env-var-based provider creation with lego's Config-based API (`NewDNSProviderConfig`) for all 4 DNS providers (Cloudflare, Route53, DuckDNS, Dynu). Fix custom Cloudflare zone provider's Content-Type bug and add DNS propagation checking. Improve connection test to validate actual DNS permissions.

**Tech Stack:** Go 1.24, lego v4.20.4, Cloudflare API v4

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `api/pkg/acme/cloudflare_zone.go` | Modify | Fix Content-Type on DELETE, add propagation checking |
| `api/pkg/acme/acme.go` | Modify | Replace env-var approach with Config-based API for all providers |
| `api/internal/repository/dns_provider.go` | Modify | Improve Cloudflare connection test to validate DNS write permissions |

---

### Task 1: Fix Content-Type Header on DELETE Requests (Bug #1 - Critical)

**Files:**
- Modify: `api/pkg/acme/cloudflare_zone.go:129-168`

This is the direct cause of Cloudflare error 6003 "Invalid request headers". The `doRequest()` method sets `Content-Type: application/json` unconditionally, including on DELETE requests with nil body. Cloudflare rejects this.

- [ ] **Step 1: Fix `doRequest()` to only set Content-Type when body is present**

In `api/pkg/acme/cloudflare_zone.go`, replace lines 129-168 with:

```go
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

	// Only set Content-Type when a body is present.
	// Cloudflare returns error 6003 "Invalid request headers" when DELETE
	// requests have Content-Type: application/json but no body.
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

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
```

- [ ] **Step 2: Build API to verify compilation**

Run: `docker compose -f docker-compose.dev.yml build api`
Expected: Build succeeds with no errors.

- [ ] **Step 3: Commit**

```bash
git add api/pkg/acme/cloudflare_zone.go
git commit -m "fix: don't set Content-Type on DELETE requests in Cloudflare zone provider

Cloudflare returns error 6003 when DELETE requests have
Content-Type: application/json but no body."
```

---

### Task 2: Add DNS Propagation Checking to Custom Zone Provider (Bug #3, #6)

**Files:**
- Modify: `api/pkg/acme/cloudflare_zone.go:1-14` (imports)
- Modify: `api/pkg/acme/cloudflare_zone.go:71-104` (Present method)

The custom `cloudflareZoneProvider.Present()` creates the TXT record and returns immediately without verifying DNS propagation. Add polling to verify the TXT record is queryable before returning.

- [ ] **Step 1: Add `net` to imports**

In `api/pkg/acme/cloudflare_zone.go`, replace the imports:

```go
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)
```

- [ ] **Step 2: Add `waitForDNSPropagation` method after `Timeout()`**

Add this method after line 127 (before `doRequest`):

```go
// waitForDNSPropagation polls public DNS resolvers until the TXT record is visible.
// This prevents ACME validation failures when Cloudflare API returns success
// but the record hasn't propagated to public DNS yet.
func (p *cloudflareZoneProvider) waitForDNSPropagation(fqdn, value string, timeout, interval time.Duration) error {
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		found := false
		for _, resolver := range resolvers {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, "udp", resolver)
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			records, err := r.LookupTXT(ctx, fqdn)
			cancel()
			if err == nil {
				for _, record := range records {
					if record == value {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if found {
			return nil
		}
		time.Sleep(interval)
	}

	// Don't fail hard - let ACME server try anyway (it may use different resolvers)
	return nil
}
```

- [ ] **Step 3: Add `context` to imports**

Update the imports to include `context`:

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)
```

- [ ] **Step 4: Call propagation check in `Present()`**

In `Present()`, add the propagation wait call before the final return. Replace the end of `Present()` (after `p.mu.Unlock()`):

```go
	p.mu.Lock()
	p.recordIDs[token] = record.ID
	p.mu.Unlock()

	// Wait for DNS propagation before signaling lego to proceed
	p.waitForDNSPropagation(info.EffectiveFQDN, info.Value, 60*time.Second, 5*time.Second)

	return nil
}
```

- [ ] **Step 5: Build API to verify compilation**

Run: `docker compose -f docker-compose.dev.yml build api`
Expected: Build succeeds with no errors.

- [ ] **Step 6: Commit**

```bash
git add api/pkg/acme/cloudflare_zone.go
git commit -m "fix: add DNS propagation checking to custom Cloudflare zone provider

Polls public resolvers (8.8.8.8, 1.1.1.1) after creating TXT record
to verify propagation before ACME validation proceeds."
```

---

### Task 3: Replace Environment Variable Approach with Config-Based API (Bug #2, #5)

**Files:**
- Modify: `api/pkg/acme/acme.go:593-698` (`createDNSProvider` function)

The current code uses `os.Setenv`/`os.Unsetenv` to pass credentials, which causes race conditions when multiple goroutines issue certificates concurrently. Replace with lego's `NewDNSProviderConfig()` that accepts credential structs directly.

- [ ] **Step 1: Replace the entire `createDNSProvider` function**

In `api/pkg/acme/acme.go`, replace lines 593-698 with:

```go
// createDNSProvider creates a DNS provider based on type and credentials.
// Uses lego's Config-based API (NewDNSProviderConfig) instead of environment variables
// to prevent race conditions when multiple goroutines issue certificates concurrently.
func (s *Service) createDNSProvider(provider *model.DNSProvider) (challenge.Provider, error) {
	if provider == nil {
		return nil, fmt.Errorf("DNS provider is required")
	}

	switch provider.ProviderType {
	case model.DNSProviderCloudflare:
		var creds model.CloudflareCredentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid cloudflare credentials: %w", err)
		}

		// If Zone ID is specified, use custom provider that bypasses SOA-based zone detection.
		// This fixes certificate issuance for domains under 2nd-level ccTLDs (e.g., .ai.kr, .pe.kr).
		if creds.ZoneID != "" {
			return newCloudflareZoneProvider(creds.ZoneID, creds.APIToken, creds.APIKey, creds.Email)
		}

		// Use Config-based API to avoid process-global env var race conditions
		cfg := cloudflare.NewDefaultConfig()
		cfg.PropagationTimeout = 180 * time.Second
		cfg.PollingInterval = 5 * time.Second
		if creds.APIToken != "" {
			cfg.AuthToken = creds.APIToken
			cfg.ZoneToken = creds.APIToken
		} else {
			cfg.AuthEmail = creds.Email
			cfg.AuthKey = creds.APIKey
		}
		return cloudflare.NewDNSProviderConfig(cfg)

	case model.DNSProviderDuckDNS:
		var creds model.DuckDNSCredentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid duckdns credentials: %w", err)
		}

		cfg := duckdns.NewDefaultConfig()
		cfg.Token = creds.Token
		return duckdns.NewDNSProviderConfig(cfg)

	case model.DNSProviderRoute53:
		var creds model.Route53Credentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid route53 credentials: %w", err)
		}

		cfg := route53.NewDefaultConfig()
		cfg.PropagationTimeout = 180 * time.Second
		cfg.PollingInterval = 5 * time.Second
		cfg.AccessKeyID = creds.AccessKeyID
		cfg.SecretAccessKey = creds.SecretAccessKey
		if creds.Region != "" {
			cfg.Region = creds.Region
		}
		if creds.HostedZoneID != "" {
			cfg.HostedZoneID = creds.HostedZoneID
		}
		return route53.NewDNSProviderConfig(cfg)

	case model.DNSProviderDynu:
		var creds model.DynuCredentials
		if err := json.Unmarshal(provider.Credentials, &creds); err != nil {
			return nil, fmt.Errorf("invalid dynu credentials: %w", err)
		}

		cfg := dynu.NewDefaultConfig()
		cfg.APIKey = creds.APIKey
		return dynu.NewDNSProviderConfig(cfg)

	default:
		return nil, fmt.Errorf("unsupported DNS provider type: %s", provider.ProviderType)
	}
}
```

- [ ] **Step 2: Remove unused `os` import if no longer needed**

Check if `os` is still used in `acme.go`. It is used by `SaveCertificateFiles`, `DeleteCertificateFiles`, `createUser`, `webrootProvider`, etc. The `os` import stays.

- [ ] **Step 3: Add `time` to imports if not already present**

Check imports at the top of `acme.go`. `time` is already imported. No change needed.

- [ ] **Step 4: Build API to verify compilation**

Run: `docker compose -f docker-compose.dev.yml build api`
Expected: Build succeeds with no errors.

- [ ] **Step 5: Commit**

```bash
git add api/pkg/acme/acme.go
git commit -m "fix: replace env-var credential passing with Config-based API

Uses lego's NewDNSProviderConfig() for all DNS providers instead of
os.Setenv/os.Unsetenv, eliminating race conditions when multiple
certificate issuances run concurrently."
```

---

### Task 4: Improve Cloudflare Connection Test (Bug #4)

**Files:**
- Modify: `api/internal/repository/dns_provider.go:284-329`

The current test calls `GET /zones?per_page=1` which returns 200 with empty results even when the token lacks `Zone:Zone:Read` permission. Improve by also attempting to list DNS records for a zone (if ZoneID is provided) or by checking the result array is non-empty.

- [ ] **Step 1: Replace `testCloudflareConnection` function**

In `api/internal/repository/dns_provider.go`, replace lines 284-329 with:

```go
func testCloudflareConnection(creds model.CloudflareCredentials) error {
	client := &http.Client{Timeout: 10 * time.Second}

	// If ZoneID is provided, verify DNS write access by listing DNS records for that zone.
	// This is more accurate than just listing zones, which can return empty for
	// tokens that only have Zone:DNS:Edit without Zone:Zone:Read.
	testURL := "https://api.cloudflare.com/client/v4/zones?per_page=1"
	if creds.ZoneID != "" {
		testURL = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?per_page=1", creds.ZoneID)
	}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if creds.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+creds.APIToken)
	} else {
		req.Header.Set("X-Auth-Email", creds.Email)
		req.Header.Set("X-Auth-Key", creds.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Cloudflare API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 {
		if creds.APIToken != "" {
			return fmt.Errorf("invalid or expired API token. Please verify the token is active in your Cloudflare dashboard")
		}
		return fmt.Errorf("invalid API key or email. Please check your Global API Key and account email")
	}

	if resp.StatusCode == 403 {
		return fmt.Errorf("insufficient permissions. API token requires Zone:DNS:Edit and Zone:Zone:Read permissions")
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("cloudflare API returned status %d: %s", resp.StatusCode, string(body))
	}

	// For zone listing (no ZoneID), verify we can actually see zones.
	// A token with Zone:DNS:Edit but not Zone:Zone:Read returns 200 with empty results,
	// which would pass the test but fail during actual certificate issuance.
	if creds.ZoneID == "" {
		var apiResp struct {
			Success    bool            `json:"success"`
			ResultInfo json.RawMessage `json:"result_info"`
			Result     []interface{}   `json:"result"`
		}
		if err := json.Unmarshal(body, &apiResp); err == nil {
			if apiResp.Success && len(apiResp.Result) == 0 {
				return fmt.Errorf("API token can connect but cannot list any zones. " +
					"Please ensure the token has Zone:Zone:Read permission, " +
					"or provide a Zone ID to bypass zone discovery")
			}
		}
	}

	return nil
}
```

- [ ] **Step 2: Add `encoding/json` to imports if not already present**

Check the imports at the top of `dns_provider.go`. `encoding/json` is already imported. No change needed.

- [ ] **Step 3: Build API to verify compilation**

Run: `docker compose -f docker-compose.dev.yml build api`
Expected: Build succeeds with no errors.

- [ ] **Step 4: Commit**

```bash
git add api/internal/repository/dns_provider.go
git commit -m "fix: improve Cloudflare connection test to detect insufficient permissions

When ZoneID is provided, test DNS record access directly.
When no ZoneID, check that zone listing returns results to catch
tokens with Zone:DNS:Edit but missing Zone:Zone:Read."
```

---

### Task 5: E2E Verification

- [ ] **Step 1: Build and deploy E2E test environment**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
sudo docker compose -f docker-compose.e2e-test.yml up -d api
```

- [ ] **Step 2: Run certificate-related E2E tests**

```bash
cd test/e2e && npx playwright test specs/certificates/
```

If no certificate-specific E2E tests exist, verify the API starts and serves health:

```bash
curl -s http://localhost:19080/health | jq .
```

Expected: `{"status":"healthy", ...}`

- [ ] **Step 3: Build production images to verify all clean**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build succeeds with no errors or warnings.
