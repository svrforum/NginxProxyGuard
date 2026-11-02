package acme

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"nginx-proxy-guard/internal/model"
)

const (
	route53StaticKeyID  = "AKIASTATICKEYID00001"
	route53StaticSecret = "static/secret+key0123456789"
	route53EnvKeyID     = "AKIAENVCHAINKEYID001"
	route53EnvSecret    = "env/secret+key0123456789"
)

// fakeRoute53 stands in for the Route 53 API: it records the SigV4
// Authorization header of every request and refuses it. The AWS SDK is
// pointed at it through AWS_ENDPOINT_URL. The default credential chain is cut
// down to its environment step: the instance metadata service is off and the
// shared config files are missing, so a run on a developer machine or in CI
// reads nothing of its own; the environment key pair stands in for what an
// instance or task role would provide.
func fakeRoute53(t *testing.T) *[]string {
	t.Helper()
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized</Message></Error><RequestId>0</RequestId></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)

	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("AWS_ENDPOINT_URL", srv.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_ACCESS_KEY_ID", route53EnvKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", route53EnvSecret)
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	return &auths
}

// With a key pair stored, lego signs with it. With none, the AWS SDK's
// default credential chain signs — here its environment step, on a host an
// EC2 instance role or an ECS task role — so no permanent key need be
// stored. The region and hosted zone are passed on in both cases: the zone
// keeps lego from looking it up, so the first request is the record listing.
func TestRoute53ProviderSignsWithStoredKeysOrTheDefaultChain(t *testing.T) {
	for name, tc := range map[string]struct {
		creds model.Route53Credentials
		keyID string
	}{
		"stored keys":   {model.Route53Credentials{AccessKeyID: route53StaticKeyID, SecretAccessKey: route53StaticSecret, Region: "us-east-1", HostedZoneID: "Z0123456789EXAMPLE"}, route53StaticKeyID},
		"default chain": {model.Route53Credentials{UseDefaultCredentials: true, Region: "us-east-1", HostedZoneID: "Z0123456789EXAMPLE"}, route53EnvKeyID},
	} {
		t.Run(name, func(t *testing.T) {
			auths := fakeRoute53(t)

			p, err := (&Service{}).newDNS01Provider(dnsProviderOf(t, model.DNSProviderRoute53, tc.creds))
			if err != nil {
				t.Fatal(err)
			}
			timeouts, ok := p.(challenge.ProviderTimeout)
			if !ok {
				t.Fatal("the Route 53 provider has no Timeout")
			}
			if timeout, interval := timeouts.Timeout(); timeout != 180*time.Second || interval != 5*time.Second {
				t.Errorf("Timeout() = %s, %s; want 180s, 5s", timeout, interval)
			}

			err = p.Present("www.example.com", "token", "keyAuth")
			if err == nil {
				t.Fatal("Present succeeded against an API that refuses every request")
			}
			if len(*auths) == 0 {
				t.Fatalf("Present sent no request: %v", err)
			}
			if got := (*auths)[0]; !strings.Contains(got, "Credential="+tc.keyID+"/") {
				t.Errorf("Authorization = %q, want a SigV4 credential of %s", got, tc.keyID)
			}
			if !strings.Contains((*auths)[0], "/route53/aws4_request") {
				t.Errorf("Authorization = %q, want a Route 53 SigV4 signature", (*auths)[0])
			}
			for _, secret := range []string{route53StaticSecret, route53EnvSecret} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("a secret is in the error: %v", err)
				}
			}
		})
	}
}

// An incomplete row is refused when the provider is built, before any
// request. The API refuses it on create and update, but a row restored from a
// backup or edited by hand was never checked, and lego would take a row
// without keys to the default chain, here the environment's key pair (#357).
// The refusal must not quote the secret, since the certificate service
// stores the error where the viewer role can read it.
func TestRoute53ProviderRefusesAnIncompleteRow(t *testing.T) {
	for name, creds := range map[string]model.Route53Credentials{
		"no secret":     {AccessKeyID: route53StaticKeyID, Region: "us-east-1"},
		"no key id":     {SecretAccessKey: route53StaticSecret, Region: "us-east-1"},
		"no keys":       {Region: "us-east-1", HostedZoneID: "Z0123456789EXAMPLE"},
		"flag and keys": {UseDefaultCredentials: true, AccessKeyID: route53StaticKeyID, SecretAccessKey: route53StaticSecret},
	} {
		auths := fakeRoute53(t)
		_, err := (&Service{}).newDNS01Provider(dnsProviderOf(t, model.DNSProviderRoute53, creds))
		if err == nil {
			t.Errorf("%s: a provider was built from %+v", name, creds)
		} else if strings.Contains(err.Error(), route53StaticSecret) {
			t.Errorf("%s: the secret is in the error: %v", name, err)
		}
		if len(*auths) != 0 {
			t.Errorf("%s: %d requests were sent", name, len(*auths))
		}
	}
}
