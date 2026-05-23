package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

type ProxyHostTester struct {
	proxyHost  string // nginx-guard-proxy hostname
	proxyHTTP  int    // HTTP port (80)
	proxyHTTPS int    // HTTPS port (443)
}

func NewProxyHostTester() *ProxyHostTester {
	proxyHost := os.Getenv("NGINX_PROXY_HOST")
	if proxyHost == "" {
		proxyHost = "host.docker.internal" // nginx runs in host network mode
	}

	return &ProxyHostTester{
		proxyHost:  proxyHost,
		proxyHTTP:  80,
		proxyHTTPS: 443,
	}
}

func (t *ProxyHostTester) TestHost(ctx context.Context, host *model.ProxyHost, targetURL string) (*model.ProxyHostTestResult, error) {
	if host.IsStream() {
		return t.testStreamProxy(ctx, host, targetURL), nil
	}

	domain := host.DomainNames[0]
	result := &model.ProxyHostTestResult{
		Domain:   domain,
		TestedAt: time.Now(),
		Headers:  make(map[string]string),
	}

	// Determine scheme based on host configuration
	scheme := "http"
	if host.SSLEnabled {
		scheme = "https"
	}

	// Build the test URL - use actual domain for external access
	var testURL string
	if targetURL != "" {
		// If custom URL provided, test that directly
		testURL = targetURL
	} else {
		// Test via actual domain (external access)
		testURL = fmt.Sprintf("%s://%s/", scheme, domain)
	}

	// Create custom transport for this request
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,   // Allow self-signed certs for testing
			ServerName:         domain, // SNI for correct certificate selection
		},
		ForceAttemptHTTP2: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result, nil
	}

	// Host header is automatically set from the URL when using actual domain

	req.Header.Set("User-Agent", "nginx-guard-tester/1.0")
	req.Header.Set("Accept", "*/*")

	// Make request and measure time
	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := time.Since(startTime).Milliseconds()
	result.ResponseTime = responseTime

	if err != nil {
		result.Error = fmt.Sprintf("Request failed: %v", err)
		result.Success = false

		// Add helpful error context
		if strings.Contains(err.Error(), "connection refused") {
			result.Error = fmt.Sprintf("Connection refused to %s. Make sure the server is running and accessible.", domain)
		} else if strings.Contains(err.Error(), "no such host") {
			result.Error = fmt.Sprintf("Cannot resolve hostname '%s'. Check DNS configuration.", domain)
		} else if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls") {
			result.Error = fmt.Sprintf("SSL/TLS error for %s: %v", domain, err)
		}

		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 500

	// Collect response headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			result.Headers[key] = values[0]
		}
	}

	// Test SSL
	result.SSL = t.testSSL(host, resp, testURL)

	// Test HTTP/2, HTTP/3
	result.HTTP = t.testHTTP(host, resp)

	// Test Cache
	result.Cache = t.testCache(host, resp)

	// Test Security Headers
	result.Security = t.testSecurity(resp)

	return result, nil
}

// TestUpstream tests connectivity to the upstream server directly
func (t *ProxyHostTester) TestUpstream(ctx context.Context, host *model.ProxyHost) (*model.ProxyHostTestResult, error) {
	if host.IsStream() {
		return t.testStreamUpstream(ctx, host), nil
	}

	result := &model.ProxyHostTestResult{
		Domain:   fmt.Sprintf("%s:%d", host.ForwardHost, host.ForwardPort),
		TestedAt: time.Now(),
		Headers:  make(map[string]string),
	}

	// Build upstream URL
	upstreamURL := fmt.Sprintf("%s://%s:%d/", host.ForwardScheme, host.ForwardHost, host.ForwardPort)

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", upstreamURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result, nil
	}

	startTime := time.Now()
	resp, err := client.Do(req)
	result.ResponseTime = time.Since(startTime).Milliseconds()

	if err != nil {
		result.Error = fmt.Sprintf("Upstream connection failed: %v", err)
		result.Success = false
		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 500

	return result, nil
}

func (t *ProxyHostTester) testStreamProxy(ctx context.Context, host *model.ProxyHost, targetURL string) *model.ProxyHostTestResult {
	protocol := model.NormalizeStreamProtocol(host.StreamProtocol)
	targetAddress, err := t.streamProxyAddress(host, targetURL)
	result := &model.ProxyHostTestResult{
		Domain:   streamDisplayName(host, targetAddress),
		TestedAt: time.Now(),
		Stream: &model.StreamTestResult{
			Protocol:         protocol,
			TargetAddress:    targetAddress,
			UpstreamAddress:  net.JoinHostPort(host.ForwardHost, strconv.Itoa(host.ForwardPort)),
			SSLPreread:       host.StreamSSLPreread,
			ProxyProtocolIn:  host.StreamAcceptProxyProtocol,
			ProxyProtocolOut: host.StreamSendProxyProtocol,
		},
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}

	responseTime, err := dialStream(ctx, protocol, targetAddress, 10*time.Second)
	result.ResponseTime = responseTime
	if err != nil {
		result.Error = streamDialError("Stream listener", targetAddress, err)
		return result
	}

	result.Success = true
	return result
}

func (t *ProxyHostTester) testStreamUpstream(ctx context.Context, host *model.ProxyHost) *model.ProxyHostTestResult {
	protocol := model.NormalizeStreamProtocol(host.StreamProtocol)
	address := net.JoinHostPort(host.ForwardHost, strconv.Itoa(host.ForwardPort))
	result := &model.ProxyHostTestResult{
		Domain:   address,
		TestedAt: time.Now(),
		Stream: &model.StreamTestResult{
			Protocol:        protocol,
			TargetAddress:   address,
			UpstreamAddress: address,
			SSLPreread:      host.StreamSSLPreread,
		},
	}

	responseTime, err := dialStream(ctx, protocol, address, 5*time.Second)
	result.ResponseTime = responseTime
	if err != nil {
		result.Error = streamDialError("Stream upstream", address, err)
		return result
	}

	result.Success = true
	return result
}

func (t *ProxyHostTester) streamProxyAddress(host *model.ProxyHost, targetURL string) (string, error) {
	// SSRF guard: targetURL is an authenticated-user-supplied value. Without
	// restriction it lets an operator probe arbitrary host:port reachable from
	// the API container (internal DB on 5432, Valkey on 6379, other services
	// on the docker network). Only allow override when the parsed address
	// resolves to the host's own configured listener — the test is meant to
	// verify the listener works, not to be a generic port scanner.
	if strings.TrimSpace(targetURL) != "" {
		parsed, err := parseStreamAddress(targetURL)
		if err != nil {
			return "", err
		}
		if err := t.assertStreamTargetAllowed(host, parsed); err != nil {
			return "", err
		}
		return parsed, nil
	}

	listenHost := strings.TrimSpace(host.StreamListenHost)
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" || listenHost == "*" {
		listenHost = t.proxyHost
	}
	if host.StreamListenPort < 1 || host.StreamListenPort > 65535 {
		return "", fmt.Errorf("stream listen port is not configured")
	}
	return net.JoinHostPort(listenHost, strconv.Itoa(host.StreamListenPort)), nil
}

// assertStreamTargetAllowed restricts the user-supplied target to the host's
// own listener (port must match, host must be empty/wildcard or match the
// configured StreamListenHost / NPG's external proxy host). This is the
// SSRF mitigation referenced in v2.18.0 PR #143 review.
func (t *ProxyHostTester) assertStreamTargetAllowed(host *model.ProxyHost, parsed string) error {
	parsedHost, parsedPort, err := net.SplitHostPort(parsed)
	if err != nil {
		return fmt.Errorf("stream target must be host:port: %w", err)
	}
	if port, perr := strconv.Atoi(parsedPort); perr != nil || port != host.StreamListenPort {
		return fmt.Errorf("stream target port %s is not allowed: must match host listener port %d", parsedPort, host.StreamListenPort)
	}
	listen := strings.TrimSpace(host.StreamListenHost)
	allowed := map[string]struct{}{
		"":          {},
		"*":         {},
		"0.0.0.0":   {},
		"::":        {},
		"127.0.0.1": {},
		"localhost": {},
	}
	if listen != "" {
		allowed[listen] = struct{}{}
	}
	if strings.TrimSpace(t.proxyHost) != "" {
		allowed[t.proxyHost] = struct{}{}
	}
	if _, ok := allowed[parsedHost]; !ok {
		return fmt.Errorf("stream target host %q is not allowed: must match host's configured listener or the proxy host", parsedHost)
	}
	return nil
}

func parseStreamAddress(raw string) (string, error) {
	address := strings.TrimSpace(raw)
	if address == "" {
		return "", fmt.Errorf("stream target address is required")
	}
	if strings.Contains(address, "://") {
		parts := strings.SplitN(address, "://", 2)
		address = parts[1]
		if slash := strings.Index(address, "/"); slash >= 0 {
			address = address[:slash]
		}
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return "", fmt.Errorf("stream target must be host:port: %w", err)
	}
	return address, nil
}

func dialStream(ctx context.Context, protocol, address string, timeout time.Duration) (int64, error) {
	network := model.NormalizeStreamProtocol(protocol)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startTime := time.Now()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, network, address)
	responseTime := time.Since(startTime).Milliseconds()
	if err != nil {
		return responseTime, err
	}
	_ = conn.Close()
	return responseTime, nil
}

func streamDisplayName(host *model.ProxyHost, fallback string) string {
	for _, name := range host.DomainNames {
		if strings.TrimSpace(name) != "" {
			return name
		}
	}
	return fallback
}

func streamDialError(label, address string, err error) string {
	errText := err.Error()
	if strings.Contains(errText, "connection refused") {
		return fmt.Sprintf("%s refused connection at %s. Check the listener, target service, and firewall.", label, address)
	}
	if strings.Contains(errText, "no such host") {
		return fmt.Sprintf("Cannot resolve stream address '%s'. Check DNS or listen host settings.", address)
	}
	if strings.Contains(errText, "i/o timeout") || strings.Contains(errText, "deadline exceeded") {
		return fmt.Sprintf("%s timed out at %s.", label, address)
	}
	return fmt.Sprintf("%s test failed for %s: %v", label, address, err)
}

func (t *ProxyHostTester) testSSL(host *model.ProxyHost, resp *http.Response, testURL string) *model.SSLTestResult {
	sslResult := &model.SSLTestResult{
		Enabled: host.SSLEnabled,
	}

	if !host.SSLEnabled {
		return sslResult
	}

	if resp.TLS != nil {
		sslResult.Valid = true
		sslResult.Protocol = tlsVersionToString(resp.TLS.Version)
		sslResult.Cipher = tls.CipherSuiteName(resp.TLS.CipherSuite)

		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			sslResult.Issuer = cert.Issuer.CommonName
			sslResult.Subject = cert.Subject.CommonName
			sslResult.NotBefore = cert.NotBefore.Format(time.RFC3339)
			sslResult.NotAfter = cert.NotAfter.Format(time.RFC3339)
			sslResult.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
		}
	} else {
		sslResult.Valid = false
		sslResult.Error = "No TLS connection established"
	}

	return sslResult
}

func (t *ProxyHostTester) testHTTP(host *model.ProxyHost, resp *http.Response) *model.HTTPTestResult {
	httpResult := &model.HTTPTestResult{}

	// Check protocol version
	httpResult.Protocol = resp.Proto
	httpResult.HTTP2Enabled = resp.ProtoMajor == 2

	// Check Alt-Svc header for HTTP/3 support
	altSvc := resp.Header.Get("Alt-Svc")
	if altSvc != "" {
		httpResult.AltSvcHeader = altSvc
		httpResult.HTTP3Enabled = strings.Contains(altSvc, "h3")
	} else {
		httpResult.HTTP3Enabled = false
	}

	return httpResult
}

func (t *ProxyHostTester) testCache(host *model.ProxyHost, resp *http.Response) *model.CacheTestResult {
	cacheResult := &model.CacheTestResult{
		Enabled: host.CacheEnabled,
	}

	// Check X-Cache-Status header (nginx proxy_cache)
	cacheStatus := resp.Header.Get("X-Cache-Status")
	if cacheStatus != "" {
		cacheResult.CacheStatus = cacheStatus
	}

	// Check Cache-Control header
	cacheControl := resp.Header.Get("Cache-Control")
	if cacheControl != "" {
		cacheResult.CacheControl = cacheControl
	}

	// Check Expires header
	expires := resp.Header.Get("Expires")
	if expires != "" {
		cacheResult.Expires = expires
	}

	// Check ETag
	etag := resp.Header.Get("ETag")
	if etag != "" {
		cacheResult.ETag = etag
	}

	// Check Last-Modified
	lastModified := resp.Header.Get("Last-Modified")
	if lastModified != "" {
		cacheResult.LastModified = lastModified
	}

	return cacheResult
}

func (t *ProxyHostTester) testSecurity(resp *http.Response) *model.SecurityTestResult {
	secResult := &model.SecurityTestResult{}

	// HSTS
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts != "" {
		secResult.HSTS = true
		secResult.HSTSValue = hsts
	}

	// X-Frame-Options
	xfo := resp.Header.Get("X-Frame-Options")
	if xfo != "" {
		secResult.XFrameOptions = xfo
	}

	// X-Content-Type-Options
	xcto := resp.Header.Get("X-Content-Type-Options")
	if xcto != "" {
		secResult.XContentTypeOptions = xcto
	}

	// Content-Security-Policy
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		secResult.ContentSecurityPolicy = csp
	}

	// X-XSS-Protection
	xss := resp.Header.Get("X-XSS-Protection")
	if xss != "" {
		secResult.XSSProtection = xss
	}

	// Referrer-Policy
	rp := resp.Header.Get("Referrer-Policy")
	if rp != "" {
		secResult.ReferrerPolicy = rp
	}

	// Permissions-Policy
	pp := resp.Header.Get("Permissions-Policy")
	if pp != "" {
		secResult.PermissionsPolicy = pp
	}

	// Server header (should be hidden for security)
	server := resp.Header.Get("Server")
	if server != "" {
		secResult.ServerHeader = server
	}

	return secResult
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
