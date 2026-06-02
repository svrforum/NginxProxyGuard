package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// parseTraceIP extracts the "ip=" value from a Cloudflare /cdn-cgi/trace body.
func parseTraceIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// PublicIPDetector resolves the server's public IPv4 via external services.
type PublicIPDetector struct {
	client   *http.Client
	traceURL string // Cloudflare trace
	plainURL string // ipify (returns bare IP)
}

func NewPublicIPDetector() *PublicIPDetector {
	return &PublicIPDetector{
		client:   &http.Client{Timeout: 10 * time.Second},
		traceURL: "https://1.1.1.1/cdn-cgi/trace",
		plainURL: "https://api.ipify.org",
	}
}

// DetectPublicIPv4 returns the public IPv4, trying the trace endpoint then ipify.
// Returns an error only if all sources fail (caller keeps last-known-good).
func (d *PublicIPDetector) DetectPublicIPv4(ctx context.Context) (string, error) {
	if ip := d.fetchValidIPv4(ctx, d.traceURL, true); ip != "" {
		return ip, nil
	}
	if ip := d.fetchValidIPv4(ctx, d.plainURL, false); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("public IPv4 detection failed (all sources)")
}

func (d *PublicIPDetector) fetchValidIPv4(ctx context.Context, url string, trace bool) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(b))
	if trace {
		raw = parseTraceIP(string(b))
	}
	ip := net.ParseIP(raw)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
}
