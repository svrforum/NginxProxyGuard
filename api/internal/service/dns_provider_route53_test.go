package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A Route 53 row is accepted with an access key pair or with none, and stored
// as given: with no keys, lego leaves authentication to the AWS SDK's default
// credential chain (environment, shared config files, ECS task role, EC2
// instance role), so a host needs no permanent key. One key without the other
// is refused on create and on update (ErrInvalidCredentials, a 400) instead
// of failing at issuance. The check goes through the real repository check,
// which touches no database for Route 53; ionosProvRepo wraps it and keeps
// what would be stored.
func TestRoute53CredentialsAcceptBothKeysOrNeither(t *testing.T) {
	const secret = "aws/secret+key0123456789"
	existing := &model.DNSProvider{ID: "p1", ProviderType: model.DNSProviderRoute53,
		Credentials: json.RawMessage(`{"access_key_id":"AKIAEXAMPLEKEYID","secret_access_key":"aws/secret+key0123456789"}`)}

	for _, tc := range []struct {
		creds    string
		accepted bool
	}{
		{`{"access_key_id":"AKIAEXAMPLEKEYID","secret_access_key":"aws/secret+key0123456789","region":"eu-west-1"}`, true},
		{`{"region":"eu-west-1","hosted_zone_id":"Z0123456789EXAMPLE"}`, true},
		{`{}`, true},
		{`{"access_key_id":"AKIAEXAMPLEKEYID"}`, false},
		{`{"secret_access_key":"aws/secret+key0123456789"}`, false},
	} {
		raw := json.RawMessage(tc.creds)

		create := &ionosProvRepo{}
		_, createErr := (&DNSProviderService{repo: create}).Create(context.Background(),
			&model.CreateDNSProviderRequest{Name: "n", ProviderType: model.DNSProviderRoute53, Credentials: raw})

		update := &ionosProvRepo{fakeProvRepo: fakeProvRepo{prov: existing}}
		_, updateErr := (&DNSProviderService{repo: update}).Update(context.Background(), "p1",
			&model.UpdateDNSProviderRequest{Credentials: &raw})

		for op, got := range map[string]struct {
			err    error
			stored json.RawMessage
		}{"create": {createErr, create.stored}, "update": {updateErr, update.stored}} {
			if !tc.accepted {
				if !errors.Is(got.err, model.ErrInvalidCredentials) {
					t.Errorf("%s %s: err = %v, want ErrInvalidCredentials", op, tc.creds, got.err)
				} else if strings.Contains(got.err.Error(), secret) {
					t.Errorf("%s %s: the secret is in the error: %v", op, tc.creds, got.err)
				}
				if got.stored != nil {
					t.Errorf("%s %s: stored %s", op, tc.creds, got.stored)
				}
				continue
			}
			if got.err != nil {
				t.Errorf("%s %s: %v", op, tc.creds, got.err)
				continue
			}
			if string(got.stored) != tc.creds {
				t.Errorf("%s %s: stored %s", op, tc.creds, got.stored)
			}
		}
	}
}
