package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// The edit form opens on the stored region; without it, re-entering the keys
// of an ovh-ca or ovh-us row saved them under ovh-eu.
func TestMaskCredentialsReportsOVHEndpoint(t *testing.T) {
	for _, tc := range []struct{ creds, want string }{
		{`{"endpoint":"ovh-ca","application_key":"ak-example","application_secret":"as-example","consumer_key":"ck-example"}`, "ovh-ca"},
		{`{"application_key":"ak-example","application_secret":"as-example","consumer_key":"ck-example"}`, "ovh-eu"},
	} {
		p := &DNSProvider{ProviderType: DNSProviderOVH, Credentials: json.RawMessage(tc.creds)}
		masked := p.MaskCredentials()
		if masked.Endpoint != tc.want {
			t.Errorf("%s: endpoint = %q, want %q", tc.creds, masked.Endpoint, tc.want)
		}
		body, _ := json.Marshal(masked)
		for _, secret := range []string{"as-example", "ck-example"} {
			if strings.Contains(string(body), secret) {
				t.Errorf("the response carries %q: %s", secret, body)
			}
		}
	}
	other := &DNSProvider{ProviderType: DNSProviderCloudflare, Credentials: json.RawMessage(`{"api_token":"x","endpoint":"ovh-ca"}`)}
	if e := other.MaskCredentials().Endpoint; e != "" {
		t.Errorf("cloudflare row reports endpoint %q", e)
	}
}
