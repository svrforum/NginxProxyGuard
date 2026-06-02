package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func renderStream(t *testing.T, host *model.ProxyHost, certExists bool) string {
	t.Helper()
	tmp := t.TempDir()
	m := NewManager(filepath.Join(tmp, "nginx.conf"), filepath.Join(tmp, "certs"))
	if certExists && host.CertificateID != nil {
		dir := filepath.Join(tmp, "certs", *host.CertificateID)
		os.MkdirAll(dir, 0755)
		os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte("x"), 0644)
		os.WriteFile(filepath.Join(dir, "privkey.pem"), []byte("x"), 0644)
	}
	if err := m.GenerateStreamConfig(nil, ProxyHostConfigData{Host: host}); err != nil {
		t.Fatalf("GenerateStreamConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(m.configPath), "stream.d", GetStreamConfigFilename(host)))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return string(b)
}

func baseStream() *model.ProxyHost {
	return &model.ProxyHost{
		ID: "h1", ProxyType: "stream", Enabled: true, DomainNames: []string{"s.example.com"},
		StreamProtocol: "tcp", StreamListenPort: 18888, ForwardHost: "10.0.0.5", ForwardPort: 8888,
	}
}

func TestStreamTerminate_EmitsSSL(t *testing.T) {
	h := baseStream()
	h.SSLEnabled = true
	cid := "cert-1"
	h.CertificateID = &cid
	out := renderStream(t, h, true)
	for _, want := range []string{"listen", " ssl", "ssl_certificate /etc/nginx/certs/cert-1/fullchain.pem;", "ssl_certificate_key /etc/nginx/certs/cert-1/privkey.pem;", "ssl_protocols TLSv1.2 TLSv1.3;"} {
		if !strings.Contains(out, want) {
			t.Fatalf("terminate output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ssl_preread on;") {
		t.Fatalf("terminate must not emit ssl_preread:\n%s", out)
	}
}

func TestStreamTerminate_MissingCertDegrades(t *testing.T) {
	h := baseStream()
	h.SSLEnabled = true
	cid := "cert-x"
	h.CertificateID = &cid
	out := renderStream(t, h, false) // cert files absent
	if strings.Contains(out, "ssl_certificate ") || strings.Contains(out, " ssl;") {
		t.Fatalf("missing cert should degrade (no ssl emitted):\n%s", out)
	}
}

func TestStreamPassthrough_EmitsPreread(t *testing.T) {
	h := baseStream()
	h.StreamSSLPreread = true
	out := renderStream(t, h, false)
	if !strings.Contains(out, "ssl_preread on;") {
		t.Fatalf("passthrough missing ssl_preread:\n%s", out)
	}
	if strings.Contains(out, "ssl_certificate ") {
		t.Fatalf("passthrough must not emit cert:\n%s", out)
	}
}
