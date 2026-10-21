package service

import (
	"errors"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A DNS-01 record that is not confirmed in time gets the advice about
// Cloudflare's token permissions only when the provider is Cloudflare. For the
// others the cause is slow propagation or nameservers that do not answer
// (#327), and the original error is kept.
func TestDiagnoseDNS01ErrorGivesZoneAdviceOnlyForCloudflare(t *testing.T) {
	timedOut := errors.New("failed to obtain certificate: error: one or more domains had a problem:\n" +
		"[example.com] propagation: time limit exceeded: last error: " +
		"TXT record for _acme-challenge.example.com. not visible yet: authoritative nameservers: not confirmed; resolver: no such record")

	if got := diagnoseDNS01Error(timedOut, model.DNSProviderCloudflare); !strings.Contains(got, "Zone:Read") {
		t.Errorf("Cloudflare lost the token permission advice: %s", got)
	}
	for _, providerType := range []string{model.DNSProviderDynu, model.DNSProviderRoute53, model.DNSProviderDuckDNS, model.DNSProviderIonos} {
		got := diagnoseDNS01Error(timedOut, providerType)
		if strings.Contains(got, "Zone") {
			t.Errorf("%s gets Cloudflare's token advice: %s", providerType, got)
		}
		for _, want := range []string{"DNS propagation timeout", "nameservers are not responding", timedOut.Error()} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q is missing from %s", providerType, want, got)
			}
		}
	}
}

// Credentials the DNS provider rejects are reported as such, whatever the
// provider.
func TestDiagnoseDNS01ErrorReportsRejectedCredentialsForEveryProvider(t *testing.T) {
	rejected := errors.New("[example.com] acme: error presenting token: unexpected status code: [status code: 401] body: {}")
	for _, providerType := range []string{model.DNSProviderCloudflare, model.DNSProviderDynu, model.DNSProviderRoute53, model.DNSProviderDuckDNS, model.DNSProviderIonos} {
		got := diagnoseDNS01Error(rejected, providerType)
		if !strings.HasPrefix(got, "Authentication failed:") || !strings.Contains(got, rejected.Error()) {
			t.Errorf("%s: %s", providerType, got)
		}
	}
}
