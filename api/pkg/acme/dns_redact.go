package acme

import (
	"encoding/json"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/redact"
)

// DNS-01 provider errors, with the provider's credentials cut out.
//
// lego keeps the error a DNS provider returns: it becomes the error
// ObtainCertificate and RenewCertificate return, and a failed clean-up is
// printed through lego's own logger, which NPG leaves at its default, stderr —
// the container log. DuckDNS takes its token in the request URL, and lego's
// DuckDNS client quotes that URL whenever DuckDNS answers anything but OK
// ("... used url [https://www.duckdns.org/update?...&token=...]") and, through
// net/http, whenever DuckDNS cannot be reached (`Get "<URL>": ...`). The
// certificate service stores that text in certificates.error_message, which the
// viewer role can read, in the certificate history and its logs, and in the
// cert.renewal_failed notification, so the token went everywhere a renewal
// failure is reported.
//
// So every error the provider hands lego is redacted by value first: the
// stored credentials, as written and as a query string or a path carries them.
// The other providers keep their credentials in request headers, which these
// wordings do not quote, and are wrapped all the same so that no wording
// anyone adds later can carry them out either.

// dnsProviderSecrets lists the credential values of a DNS provider: the
// Cloudflare token and global API key, the DuckDNS token, the Route53 secret
// key and the Dynu API key. Identifiers that are not credentials — an e-mail
// address, a zone ID, a region, an access key ID — stay readable.
func dnsProviderSecrets(provider *model.DNSProvider) *redact.Secrets {
	var creds struct {
		APIToken        string `json:"api_token"`
		APIKey          string `json:"api_key"`
		Token           string `json:"token"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if provider != nil {
		// Credentials that do not parse are refused by createDNSProvider, with
		// an error that quotes none of them.
		_ = json.Unmarshal(provider.Credentials, &creds)
	}
	secrets := &redact.Secrets{}
	secrets.Add(creds.APIToken, creds.APIKey, creds.Token, creds.SecretAccessKey)
	return secrets
}

// newDNS01Provider returns the provider createDNSProvider builds, wrapped so
// that no error — from creating it, or later from presenting or cleaning up a
// record — carries the provider's credentials.
func (s *Service) newDNS01Provider(provider *model.DNSProvider) (challenge.Provider, error) {
	secrets := dnsProviderSecrets(provider)
	inner, err := s.createDNSProvider(provider)
	if err != nil {
		return nil, secrets.Error(err)
	}
	redacting := &redactingDNSProvider{inner: inner, secrets: secrets}
	// lego solves the domains of a provider with Sequential one at a time, and
	// DuckDNS needs that: it keeps one TXT record for a domain and all its
	// subdomains. The wrapper must not hide the method, nor add it to a
	// provider that lacks it.
	if seq, ok := inner.(interface{ Sequential() time.Duration }); ok {
		return &sequentialRedactingDNSProvider{redactingDNSProvider: redacting, seq: seq}, nil
	}
	return redacting, nil
}

type redactingDNSProvider struct {
	inner   challenge.Provider
	secrets *redact.Secrets
}

func (p *redactingDNSProvider) Present(domain, token, keyAuth string) error {
	return p.secrets.Error(p.inner.Present(domain, token, keyAuth))
}

func (p *redactingDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return p.secrets.Error(p.inner.CleanUp(domain, token, keyAuth))
}

// Timeout passes on the provider's propagation timeout. For a provider without
// one it returns the defaults lego would have used.
func (p *redactingDNSProvider) Timeout() (timeout, interval time.Duration) {
	if t, ok := p.inner.(challenge.ProviderTimeout); ok {
		return t.Timeout()
	}
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

type sequentialRedactingDNSProvider struct {
	*redactingDNSProvider
	seq interface{ Sequential() time.Duration }
}

func (p *sequentialRedactingDNSProvider) Sequential() time.Duration { return p.seq.Sequential() }
