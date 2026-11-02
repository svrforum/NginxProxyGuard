package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A Route 53 row authenticates with an access key pair, or with
// use_default_credentials and no keys: lego then leaves it to the AWS SDK's
// default credential chain (environment, shared config files, ECS task role,
// EC2 instance role). Missing keys without the flag are refused: an edit form
// with blank key fields sends exactly that, and it must not switch the
// provider to the host's role (#357).
func TestRoute53CredentialsNeedKeysOrTheFlag(t *testing.T) {
	const secret = "aws/secret+key0123456789"
	for _, tc := range []struct {
		creds        string
		valid        bool
		defaultChain bool
	}{
		{`{"access_key_id":"AKIAEXAMPLEKEYID","secret_access_key":"aws/secret+key0123456789","region":"eu-west-1"}`, true, false},
		{`{"use_default_credentials":true,"region":"eu-west-1","hosted_zone_id":"Z0123456789EXAMPLE"}`, true, true},
		{`{"use_default_credentials":true,"access_key_id":"","secret_access_key":""}`, true, true},
		{`{"region":"eu-west-1","hosted_zone_id":"Z0123456789EXAMPLE"}`, false, false},
		{`{}`, false, false},
		{`{"access_key_id":"","secret_access_key":""}`, false, false},
		{`{"use_default_credentials":true,"access_key_id":"AKIAEXAMPLEKEYID","secret_access_key":"aws/secret+key0123456789"}`, false, true},
		{`{"access_key_id":"AKIAEXAMPLEKEYID"}`, false, false},
		{`{"secret_access_key":"aws/secret+key0123456789"}`, false, false},
		{`{"access_key_id":"","secret_access_key":"aws/secret+key0123456789"}`, false, false},
	} {
		p := &DNSProvider{ProviderType: DNSProviderRoute53, Credentials: json.RawMessage(tc.creds)}
		err := p.ValidateCredentials()
		if tc.valid && err != nil {
			t.Errorf("%s: %v", tc.creds, err)
		}
		if !tc.valid {
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("%s: err = %v, want ErrInvalidCredentials", tc.creds, err)
			} else if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the secret is in the error: %v", tc.creds, err)
			}
		}

		var creds Route53Credentials
		if err := json.Unmarshal([]byte(tc.creds), &creds); err != nil {
			t.Fatal(err)
		}
		if got := creds.UsesDefaultCredentialChain(); got != tc.defaultChain {
			t.Errorf("%s: UsesDefaultCredentialChain() = %v, want %v", tc.creds, got, tc.defaultChain)
		}
	}
}

// The edit form needs the choice, never the keys (#357).
func TestMaskCredentialsReportsRoute53DefaultCredentials(t *testing.T) {
	for _, tc := range []struct {
		providerType, creds string
		want                bool
	}{
		{DNSProviderRoute53, `{"use_default_credentials":true,"region":"eu-west-1"}`, true},
		{DNSProviderRoute53, `{"access_key_id":"AKIAEXAMPLEKEYID","secret_access_key":"aws/secret+key0123456789"}`, false},
		{DNSProviderCloudflare, `{"api_token":"cf-token-0123456789","use_default_credentials":true}`, false},
	} {
		p := &DNSProvider{ProviderType: tc.providerType, Credentials: json.RawMessage(tc.creds)}
		masked := p.MaskCredentials()
		if masked.UseDefaultCredentials != tc.want {
			t.Errorf("%s %s: use_default_credentials = %v, want %v", tc.providerType, tc.creds, masked.UseDefaultCredentials, tc.want)
		}
		body, err := json.Marshal(masked)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"AKIAEXAMPLEKEYID", "aws/secret", "cf-token"} {
			if strings.Contains(string(body), secret) {
				t.Errorf("%s: the response carries %q: %s", tc.providerType, secret, body)
			}
		}
	}
}
