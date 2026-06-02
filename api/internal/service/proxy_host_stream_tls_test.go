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
