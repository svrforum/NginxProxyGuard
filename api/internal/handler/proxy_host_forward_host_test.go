package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/service"
)

// POST /proxy-hosts with a bracketed IPv6 forward host, the form #314 reported
// as "invalid forward_host format", must get past the handler's forward_host
// check. Every request here also carries an invalid tag, which the service
// rejects before it touches the database, so each one ends in a 400 whose
// message shows which of the two checks fired.
func TestCreateProxyHostAcceptsBracketedIPv6ForwardHost(t *testing.T) {
	h := NewProxyHostHandler(&service.ProxyHostService{}, nil, nil, nil)
	for _, tc := range []struct {
		forwardHost string
		want        string
	}{
		{"[2001:db8::1]", `invalid input: tag "-bad"`},
		{"2001:db8::1", `invalid input: tag "-bad"`},
		{"[backend.example.com]", "invalid forward_host format"},
	} {
		body := `{"domain_names":["app.example.com"],"forward_host":"` + tc.forwardHost + `","forward_port":8080,"tags":["-bad"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy-hosts", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		if err := h.Create(echo.New().NewContext(req, rec)); err != nil {
			t.Fatalf("forward_host %q: %v", tc.forwardHost, err)
		}
		var resp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("forward_host %q: decode %q: %v", tc.forwardHost, rec.Body.String(), err)
		}
		if rec.Code != http.StatusBadRequest || !strings.HasPrefix(resp.Error, tc.want) {
			t.Errorf("forward_host %q: got %d %q, want 400 %q", tc.forwardHost, rec.Code, resp.Error, tc.want)
		}
	}
}
