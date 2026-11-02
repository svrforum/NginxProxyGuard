package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"github.com/lib/pq"

	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// A proxy_host_id naming no host passed the CAPTCHA and then failed on the
// token's foreign key: 500 on /verify, and on the form path a 503 page that
// refreshes forever (#356). The host is now looked up first, before any
// config or provider call — sqlmock refuses every query not expected here.
func TestVerifyRefusesAProxyHostThatDoesNotExist(t *testing.T) {
	const hostID = "123e4567-e89b-12d3-a456-426614174000"
	const referer = "https://app.example.com/page"
	exists := `SELECT EXISTS \(SELECT 1 FROM proxy_hosts WHERE id = \$1\)`
	for _, tc := range []struct {
		name, id string
		form     bool
		lookup   func(*sqlmock.ExpectedQuery)
		want     int
	}{
		{"json, unknown host", hostID, false, func(q *sqlmock.ExpectedQuery) {
			q.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		}, http.StatusNotFound},
		{"json, not an ID", "not-a-uuid", false, func(q *sqlmock.ExpectedQuery) {
			q.WillReturnError(&pq.Error{Code: "22P02"})
		}, http.StatusBadRequest},
		{"form, unknown host", hostID, true, func(q *sqlmock.ExpectedQuery) {
			q.WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		}, http.StatusFound},
		{"form, not an ID", "not-a-uuid", true, func(q *sqlmock.ExpectedQuery) {
			q.WillReturnError(&pq.Error{Code: "22P02"})
		}, http.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tc.lookup(mock.ExpectQuery(exists).WithArgs(tc.id))
			h := NewChallengeHandler(service.NewChallengeService(repository.NewChallengeRepository(db)), nil)

			var req *http.Request
			if tc.form {
				form := url.Values{"token": {"probe"}, "proxy_host_id": {tc.id}, "return_url": {"/"}}
				req = httptest.NewRequest(http.MethodPost, "/api/v1/challenge/verify-redirect", strings.NewReader(form.Encode()))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
				req.Header.Set("Referer", referer)
			} else {
				body := `{"token":"probe","proxy_host_id":"` + tc.id + `"}`
				req = httptest.NewRequest(http.MethodPost, "/api/v1/challenge/verify", strings.NewReader(body))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			}
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)
			if tc.form {
				err = h.VerifyAndRedirect(c)
			} else {
				err = h.VerifyCaptcha(c)
			}
			if err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.want, rec.Body)
			}
			if tc.form && rec.Header().Get("Location") != referer {
				t.Errorf("Location = %q, want the referer", rec.Header().Get("Location"))
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Error(err)
			}
		})
	}
}
