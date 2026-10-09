package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

const crawlerUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

var challengeTokenCols = []string{"id", "proxy_host_id", "token_hash", "client_ip", "user_agent", "challenge_reason",
	"issued_at", "expires_at", "use_count", "last_used_at", "revoked", "revoked_at", "revoked_reason"}

// nginx's /_challenge/validate gate decides who is challenged and asks the API
// only about a challenged visitor carrying a token, so the answer depends on
// the token alone. The User-Agent is the client's to choose and must not
// change it. X-Geo-Blocked: 0 stays a pass for configs rendered by older
// versions, which also ask about visitors they do not challenge; nginx sets
// that header itself.
func TestValidateTokenDecidesOnTheTokenOnly(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-0000000000a1"
	for _, tc := range []struct {
		name      string
		geo       string // X-Geo-Blocked as nginx sends it ("" = absent)
		ua, token string
		row       bool // the token exists and is valid
		queried   bool // the token must have been looked up
		want      int
	}{
		{name: "older config asks about a visitor it does not challenge", geo: "0", ua: "Mozilla/5.0", want: 200},
		{name: "crawler User-Agent, no token", geo: "1", ua: crawlerUA, want: 401},
		{name: "crawler User-Agent, unknown token", geo: "1", ua: crawlerUA, token: "x", queried: true, want: 401},
		{name: "unknown token", geo: "1", ua: "Mozilla/5.0", token: "x", queried: true, want: 401},
		{name: "valid token", geo: "1", ua: "Mozilla/5.0", token: "goodtoken", row: true, queried: true, want: 200},
		{name: "valid token, crawler User-Agent", geo: "1", ua: crawlerUA, token: "goodtoken", row: true, queried: true, want: 200},
		{name: "header missing means challenged", geo: "", ua: crawlerUA, token: "x", queried: true, want: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if tc.queried {
				rows := sqlmock.NewRows(challengeTokenCols)
				if tc.row {
					now := time.Now()
					rows.AddRow("00000000-0000-0000-0000-0000000000f1", nil, repository.HashToken(tc.token), "192.0.2.10",
						"ua", "geo_restriction", now, now.Add(time.Hour), 0, nil, false, nil, nil)
				}
				mock.ExpectQuery(`FROM challenge_tokens`).WithArgs(repository.HashToken(tc.token), hostID).WillReturnRows(rows)
				if tc.row {
					mock.ExpectExec(`UPDATE challenge_tokens SET use_count`).WillReturnResult(sqlmock.NewResult(0, 1))
				}
			}
			h := NewChallengeHandler(service.NewChallengeService(repository.NewChallengeRepository(db)), nil)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/validate", nil)
			if tc.geo != "" {
				req.Header.Set("X-Geo-Blocked", tc.geo)
			}
			req.Header.Set("User-Agent", tc.ua)
			req.Header.Set("X-Proxy-Host-ID", hostID)
			if tc.token != "" {
				req.Header.Set("X-Challenge-Token", tc.token)
			}
			rec := httptest.NewRecorder()
			if err := h.ValidateToken(echo.New().NewContext(req, rec)); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("token lookup: %v", err)
			}
		})
	}
}
