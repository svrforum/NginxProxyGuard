package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

func cidPtr(s string) *string { return &s }

func TestNormalizeCreate_StreamTLSTermination(t *testing.T) {
	// terminate: tcp + ssl_enabled + cert, no preread -> allowed, fields preserved
	req := &model.CreateProxyHostRequest{
		ProxyType: "stream", StreamProtocol: "tcp", StreamListenPort: 18888,
		ForwardHost: "10.0.0.5", ForwardPort: 8888,
		SSLEnabled: true, CertificateID: cidPtr("cert-1"), StreamSSLPreread: false,
	}
	if err := normalizeCreateProxyHostRequest(req); err != nil {
		t.Fatalf("terminate should be allowed: %v", err)
	}
	if !req.SSLEnabled || req.CertificateID == nil || *req.CertificateID != "cert-1" {
		t.Fatalf("terminate fields cleared: ssl=%v cert=%v", req.SSLEnabled, req.CertificateID)
	}
	if req.StreamSSLPreread {
		t.Fatalf("preread must be false when terminating")
	}
	// HTTP-only fields forced off
	if req.SSLHTTP2 || req.SSLForceHTTPS || req.WAFEnabled || req.CacheEnabled {
		t.Fatalf("http-only fields not forced off")
	}
}

func TestNormalizeCreate_StreamTLSExclusions(t *testing.T) {
	base := func() *model.CreateProxyHostRequest {
		return &model.CreateProxyHostRequest{ProxyType: "stream", StreamProtocol: "tcp", StreamListenPort: 1, ForwardHost: "h", ForwardPort: 2}
	}
	// terminate + preread -> error
	r := base()
	r.SSLEnabled = true
	r.CertificateID = cidPtr("c")
	r.StreamSSLPreread = true
	if err := normalizeCreateProxyHostRequest(r); err == nil {
		t.Fatal("terminate + preread must be rejected")
	}
	// terminate without cert -> error
	r = base()
	r.SSLEnabled = true
	r.CertificateID = nil
	if err := normalizeCreateProxyHostRequest(r); err == nil {
		t.Fatal("terminate without cert must be rejected")
	}
	// udp + terminate -> ssl forced off (not an error; udp can't terminate)
	r = base()
	r.StreamProtocol = "udp"
	r.SSLEnabled = true
	r.CertificateID = cidPtr("c")
	if err := normalizeCreateProxyHostRequest(r); err != nil {
		t.Fatalf("udp normalize err: %v", err)
	}
	if r.SSLEnabled || r.CertificateID != nil {
		t.Fatal("udp must force ssl off")
	}
	// passthrough: preread + no ssl -> cert cleared, preread kept
	r = base()
	r.StreamSSLPreread = true
	r.SSLEnabled = false
	r.CertificateID = cidPtr("c")
	if err := normalizeCreateProxyHostRequest(r); err != nil {
		t.Fatalf("passthrough err: %v", err)
	}
	if r.SSLEnabled || r.CertificateID != nil || !r.StreamSSLPreread {
		t.Fatal("passthrough should keep preread, clear cert/ssl")
	}
}

func TestNormalizeUpdate_StreamTLS(t *testing.T) {
	// 1. passthrough stream host -> update to terminate (ssl + cert): preread cleared.
	existing := &model.ProxyHost{
		ID: "h1", ProxyType: "stream", StreamProtocol: "tcp",
		StreamListenPort: 18888, ForwardHost: "10.0.0.5", ForwardPort: 8888,
		StreamSSLPreread: true, SSLEnabled: false,
	}
	req := &model.UpdateProxyHostRequest{
		SSLEnabled:       boolPtr(true),
		CertificateID:    cidPtr("cert-1"),
		StreamSSLPreread: boolPtr(false),
	}
	cand, err := normalizeUpdateProxyHostRequest(existing, req)
	if err != nil {
		t.Fatalf("passthrough->terminate should be allowed: %v", err)
	}
	if !cand.SSLEnabled || cand.CertificateID == nil || *cand.CertificateID != "cert-1" {
		t.Fatalf("terminate fields not applied: ssl=%v cert=%v", cand.SSLEnabled, cand.CertificateID)
	}
	if cand.StreamSSLPreread {
		t.Fatal("preread must be false when terminating")
	}

	// 2. terminate stream host -> change protocol to udp: ssl forced off, cert cleared.
	existing = &model.ProxyHost{
		ID: "h2", ProxyType: "stream", StreamProtocol: "tcp",
		StreamListenPort: 18889, ForwardHost: "10.0.0.6", ForwardPort: 8889,
		SSLEnabled: true, CertificateID: cidPtr("cert-1"), StreamSSLPreread: false,
	}
	req = &model.UpdateProxyHostRequest{
		StreamProtocol: cidPtr("udp"),
	}
	cand, err = normalizeUpdateProxyHostRequest(existing, req)
	if err != nil {
		t.Fatalf("terminate->udp normalize err: %v", err)
	}
	if cand.SSLEnabled {
		t.Fatal("udp must force ssl off")
	}
	if cand.CertificateID != nil && *cand.CertificateID != "" {
		t.Fatalf("udp must clear certificate, got %v", cand.CertificateID)
	}

	// 3. update to terminate WITHOUT cert -> error.
	existing = &model.ProxyHost{
		ID: "h3", ProxyType: "stream", StreamProtocol: "tcp",
		StreamListenPort: 18890, ForwardHost: "10.0.0.7", ForwardPort: 8890,
		StreamSSLPreread: false, SSLEnabled: false,
	}
	req = &model.UpdateProxyHostRequest{
		SSLEnabled:    boolPtr(true),
		CertificateID: cidPtr(""),
	}
	if _, err := normalizeUpdateProxyHostRequest(existing, req); err == nil {
		t.Fatal("terminate without cert must be rejected")
	}

	// 4. update to terminate WITH preread also true -> mutual-exclusion error.
	existing = &model.ProxyHost{
		ID: "h4", ProxyType: "stream", StreamProtocol: "tcp",
		StreamListenPort: 18891, ForwardHost: "10.0.0.8", ForwardPort: 8891,
		StreamSSLPreread: true, SSLEnabled: false,
	}
	req = &model.UpdateProxyHostRequest{
		SSLEnabled:       boolPtr(true),
		CertificateID:    cidPtr("cert-1"),
		StreamSSLPreread: boolPtr(true),
	}
	if _, err := normalizeUpdateProxyHostRequest(existing, req); err == nil {
		t.Fatal("terminate + preread must be rejected")
	}
}
