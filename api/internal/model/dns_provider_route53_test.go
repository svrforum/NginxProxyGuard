package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A Route 53 row authenticates with an access key pair, or with none: lego
// then leaves it to the AWS SDK's default credential chain (environment,
// shared config files, ECS task role, EC2 instance role). One key without the
// other can do neither and is refused.
func TestRoute53CredentialsAcceptBothKeysOrNeither(t *testing.T) {
	const secret = "aws/secret+key0123456789"
	for _, tc := range []struct {
		creds        string
		valid        bool
		defaultChain bool
	}{
		{`{"access_key_id":"AKIAEXAMPLEKEYID","secret_access_key":"aws/secret+key0123456789","region":"eu-west-1"}`, true, false},
		{`{"region":"eu-west-1","hosted_zone_id":"Z0123456789EXAMPLE"}`, true, true},
		{`{}`, true, true},
		{`{"access_key_id":"","secret_access_key":""}`, true, true},
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
