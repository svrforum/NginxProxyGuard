package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// legoDuckDNSError is what lego's DuckDNS client reported for a refused update
// before the ACME package redacted it: the update URL, token and all. It is the
// shape a certificate row held after a failed DNS-01 renewal.
const legoDuckDNSError = `Failed to obtain certificate via DNS-01: failed to obtain certificate: error: one or more domains had a problem:
[home.duckdns.org] [home.duckdns.org] acme: error presenting token: request to change TXT record for DuckDNS returned the following result (KO) this does not match expectation (OK) used url [https://www.duckdns.org/update?clear=false&domains=home.duckdns.org&token=7d0c5a8e-3b1f-4c2a-9e6d-1f2a3b4c5d6e&txt=Jscq]`

// The write of certificates.error_message — which the viewer role can read —
// cuts the credential out and keeps the rest of the message.
func TestCertificateErrorMessageIsStoredWithoutTheToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	repo := NewCertificateRepository(&database.DB{DB: db})

	var bound string
	mock.ExpectExec(`UPDATE certificates`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			capture{&bound}, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	msg := legoDuckDNSError
	cert := &model.Certificate{ID: testProxyHostID, Status: model.CertStatusIssued, ErrorMessage: &msg}
	if err := repo.Update(context.Background(), cert); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	if strings.Contains(bound, "7d0c5a8e") {
		t.Errorf("the DuckDNS token reached the column: %s", bound)
	}
	want := strings.Replace(legoDuckDNSError, "token=7d0c5a8e-3b1f-4c2a-9e6d-1f2a3b4c5d6e", "token=[redacted]", 1)
	if bound != want {
		t.Errorf("the rest of the message was not kept:\n got: %q\nwant: %q", bound, want)
	}
}

// Every shape persistedErrorText knows, alongside the driver scrub it already
// did. Text without either is stored byte for byte.
func TestPersistedErrorTextCutsCredentialsOutOfURLs(t *testing.T) {
	cases := map[string]string{
		`Post "https://api.telegram.org/bot123456789:AAH-x_y/sendMessage": EOF`:     `Post "https://api.telegram.org/bot[redacted]/sendMessage": EOF`,
		`Post "https://discord.com/api/webhooks/1122334455/tok-EN_x": EOF`:          `Post "https://discord.com/api/webhooks/[redacted]": EOF`,
		`Post "https://hooks.slack.com/services/T0123ABC/B0456DEF/abc123XYZ": EOF`:  `Post "https://hooks.slack.com/services/[redacted]": EOF`,
		`sync failed: token=abc-123 rejected: pq: deadlock detected (40P01)`:        `sync failed: token=[redacted] rejected: ` + database.MsgDatabaseError,
		`nginx: [emerg] duplicate location "/" in /etc/nginx/conf.d/host_1.conf:42`: `nginx: [emerg] duplicate location "/" in /etc/nginx/conf.d/host_1.conf:42`,
	}
	for in, want := range cases {
		if got := persistedErrorText(in); got != want {
			t.Errorf("persistedErrorText(%q)\n got: %q\nwant: %q", in, got, want)
		}
	}
}
