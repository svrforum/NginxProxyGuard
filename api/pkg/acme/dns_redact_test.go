package acme

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"nginx-proxy-guard/internal/model"
)

func dnsProviderOf(t *testing.T, providerType string, creds any) *model.DNSProvider {
	t.Helper()
	raw, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}
	return &model.DNSProvider{ProviderType: providerType, Credentials: raw}
}

// Wrapping a provider must not change how lego solves with it. lego solves the
// domains of a provider that has Sequential one at a time — DuckDNS keeps one
// TXT record per account, so a SAN certificate depends on it — and takes the
// propagation timeout from Timeout. A provider without Sequential must not
// gain it, or lego would serialise, and wait between, every domain.
func TestDNS01ProviderWrapperKeepsLegoSolvingBehaviour(t *testing.T) {
	s := &Service{}

	duck, err := s.newDNS01Provider(dnsProviderOf(t, model.DNSProviderDuckDNS, model.DuckDNSCredentials{Token: duckTestToken}))
	if err != nil {
		t.Fatal(err)
	}
	seq, ok := duck.(interface{ Sequential() time.Duration })
	if !ok {
		t.Fatal("the wrapped DuckDNS provider lost Sequential: lego would solve its domains in parallel")
	}
	if got := seq.Sequential(); got != dns01.DefaultPropagationTimeout {
		t.Errorf("Sequential() = %s, want lego's DuckDNS default %s", got, dns01.DefaultPropagationTimeout)
	}

	cf, err := s.newDNS01Provider(dnsProviderOf(t, model.DNSProviderCloudflare, model.CloudflareCredentials{APIToken: "cf-token-0123456789"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cf.(interface{ Sequential() time.Duration }); ok {
		t.Error("the wrapped Cloudflare provider gained Sequential")
	}
	timeouts, ok := cf.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("the wrapped provider has no Timeout")
	}
	if timeout, interval := timeouts.Timeout(); timeout != 180*time.Second || interval != 5*time.Second {
		t.Errorf("Timeout() = %s, %s; want the 180s, 5s createDNSProvider configures", timeout, interval)
	}
}

// fakeDNSProvider fails with whatever text it is given.
type fakeDNSProvider struct{ err error }

func (f fakeDNSProvider) Present(string, string, string) error { return f.err }
func (f fakeDNSProvider) CleanUp(string, string, string) error { return f.err }

// Every credential field is matched by value, as written and as a query string
// carries it; identifiers that are not credentials stay readable. A provider
// without Timeout reports lego's defaults, which is what lego used for it
// before it was wrapped.
func TestDNS01ProviderWrapperRedactsEveryCredentialField(t *testing.T) {
	cases := []struct {
		name    string
		creds   any
		secrets []string
		kept    []string
	}{
		{"cloudflare token", model.CloudflareCredentials{APIToken: "cf+token/0123456789", ZoneID: "0123456789abcdef0123456789abcdef"},
			[]string{"cf+token/0123456789", "cf%2Btoken%2F0123456789"}, []string{"0123456789abcdef0123456789abcdef"}},
		{"cloudflare global key", model.CloudflareCredentials{APIKey: "global-key-0123456789", Email: "admin@example.com"},
			[]string{"global-key-0123456789"}, []string{"admin@example.com"}},
		{"route53", model.Route53Credentials{AccessKeyID: "AKIAEXAMPLEKEYID", SecretAccessKey: "aws/secret+key0123456789"},
			[]string{"aws/secret+key0123456789", "aws%2Fsecret%2Bkey0123456789"}, []string{"AKIAEXAMPLEKEYID"}},
		{"dynu", model.DynuCredentials{APIKey: "dynu-key-0123456789"}, []string{"dynu-key-0123456789"}, nil},
		{"duckdns", model.DuckDNSCredentials{Token: duckTestToken}, []string{duckTestToken}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets := dnsProviderSecrets(dnsProviderOf(t, "", tc.creds))
			text := "provider said: " + strings.Join(append(append([]string{}, tc.secrets...), tc.kept...), " | ")
			p := &redactingDNSProvider{inner: fakeDNSProvider{errors.New(text)}, secrets: secrets}
			for name, err := range map[string]error{"Present": p.Present("d", "t", "k"), "CleanUp": p.CleanUp("d", "t", "k")} {
				for _, secret := range tc.secrets {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("%s: %q survived: %v", name, secret, err)
					}
				}
				for _, kept := range tc.kept {
					if !strings.Contains(err.Error(), kept) {
						t.Errorf("%s: %q, which is no credential, was removed: %v", name, kept, err)
					}
				}
			}
			if timeout, interval := p.Timeout(); timeout != dns01.DefaultPropagationTimeout || interval != dns01.DefaultPollingInterval {
				t.Errorf("Timeout() of a provider without one = %s, %s; want lego's defaults", timeout, interval)
			}
		})
	}
}
