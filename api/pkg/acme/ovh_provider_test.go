package acme

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func ovhProvider(t *testing.T, creds model.OVHCredentials) *model.DNSProvider {
	t.Helper()
	raw, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}
	return &model.DNSProvider{ProviderType: model.DNSProviderOVH, Credentials: raw}
}

// The three keys build a lego provider on ovh-eu by default; a missing key or
// an unknown endpoint is refused before any request, also for a row restored
// from a backup.
func TestOVHProviderCredentials(t *testing.T) {
	s := &Service{}
	ok := model.OVHCredentials{ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck"}
	if ok.APIEndpoint() != "ovh-eu" {
		t.Fatalf("default endpoint = %q", ok.APIEndpoint())
	}
	for _, e := range []string{"", "ovh-eu", "ovh-ca", "ovh-us"} {
		c := ok
		c.Endpoint = e
		if _, err := s.createDNSProvider(ovhProvider(t, c)); err != nil {
			t.Errorf("endpoint %q: %v", e, err)
		}
	}
	for name, c := range map[string]model.OVHCredentials{
		"no application key":    {ApplicationSecret: "as", ConsumerKey: "ck"},
		"no application secret": {ApplicationKey: "ak", ConsumerKey: "ck"},
		"blank consumer key":    {ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: " "},
		"unknown endpoint":      {Endpoint: "ovh-xx", ApplicationKey: "ak", ApplicationSecret: "as", ConsumerKey: "ck"},
	} {
		if _, err := s.createDNSProvider(ovhProvider(t, c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := c.Validate(); !errors.Is(err, model.ErrInvalidCredentials) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

// The application secret and consumer key never appear in an error; the
// application key is an identifier and stays readable.
func TestOVHSecretsRedacted(t *testing.T) {
	p := ovhProvider(t, model.OVHCredentials{ApplicationKey: "appkey123", ApplicationSecret: "appsecret456", ConsumerKey: "consumer789"})
	msg := dnsProviderSecrets(p).Error(errors.New("failed: appkey123 appsecret456 consumer789")).Error()
	if strings.Contains(msg, "appsecret456") || strings.Contains(msg, "consumer789") {
		t.Fatalf("secret leaked: %s", msg)
	}
	if !strings.Contains(msg, "appkey123") {
		t.Fatalf("application key hidden: %s", msg)
	}
}
