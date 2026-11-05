package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lib/pq"
)

// A malformed path id ("/proxy-hosts/not-a-uuid") reaches Postgres as a cast
// failure, and lib/pq renders the whole story back at us: the SQLSTATE, the
// column type, the offending literal, and — when the driver kept the statement —
// the line:column position inside our SQL. Before #298 every one of those
// strings was copied verbatim into the response body, so any authenticated
// caller could read our query geometry off a 500. These are the fragments that
// must never cross the wire again.
var driverTextMarkers = []string{"pq: ", "22P02", "22001", "invalid input syntax", "value too long", "at position"}

func newUUIDCastError() *pq.Error {
	return &pq.Error{
		Code:    "22P02",
		Message: `invalid input syntax for type uuid: "not-a-uuid"`,
	}
}

func assertNoDriverText(t *testing.T, label, got string) {
	t.Helper()
	for _, marker := range driverTextMarkers {
		if strings.Contains(got, marker) {
			t.Errorf("%s leaked driver text %q: %q", label, marker, got)
		}
	}
}

func TestMalformedIdentifierBecomesClientErrorWithoutDriverText(t *testing.T) {
	// The shape repositories actually produce: fmt.Errorf("...: %w", pqErr).
	err := fmt.Errorf("failed to get proxy host: %w", newUUIDCastError())

	status, msg, ok := ClientStatusForDBError(err)
	if !ok {
		t.Fatalf("ClientStatusForDBError did not classify a 22P02 wrapped with %%w")
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
	if msg != ErrMsgInvalidIdentifier {
		t.Errorf("message = %q, want %q", msg, ErrMsgInvalidIdentifier)
	}
	assertNoDriverText(t, "ClientStatusForDBError message", msg)

	// details is omitempty, so "" drops the field from the body entirely.
	if detail := SafeErrorDetail(err); detail != "" {
		t.Errorf("SafeErrorDetail = %q, want \"\"", detail)
	}
	if got := SafeErrorMessage(err); got != ErrMsgDatabaseError {
		t.Errorf("SafeErrorMessage = %q, want %q", got, ErrMsgDatabaseError)
	}
	assertNoDriverText(t, "SafeErrorMessage", SafeErrorMessage(err))
}

// A value longer than its column, with no field check in front of it (#353):
// Postgres answers 22001, which is the caller's value, so a 400 with a fixed
// message instead of a 500.
func TestOverLongValueBecomesClientErrorWithoutDriverText(t *testing.T) {
	err := fmt.Errorf("failed to update SSO provider: %w", &pq.Error{
		Code:    "22001",
		Message: "value too long for type character varying(64)",
	})

	status, msg, ok := ClientStatusForDBError(err)
	if !ok {
		t.Fatalf("ClientStatusForDBError did not classify a 22001 wrapped with %%w")
	}
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
	if msg != ErrMsgValueTooLong {
		t.Errorf("message = %q, want %q", msg, ErrMsgValueTooLong)
	}
	assertNoDriverText(t, "ClientStatusForDBError message", msg)
}

func TestOtherSQLStatesKeepTheirStatusButStillGetScrubbed(t *testing.T) {
	// 23505 is our own problem to classify (repositories already map it to
	// model.ErrDuplicateEntry), so it must stay a 500 — but the driver text
	// still must not reach the client.
	err := fmt.Errorf("failed to create user: %w", &pq.Error{
		Code:    "23505",
		Message: `duplicate key value violates unique constraint "users_username_key"`,
	})

	if _, _, ok := ClientStatusForDBError(err); ok {
		t.Error("ClientStatusForDBError classified 23505; it must stay a 500")
	}
	if detail := SafeErrorDetail(err); detail != "" {
		t.Errorf("SafeErrorDetail = %q, want \"\"", detail)
	}
	if got := SafeErrorMessage(err); got != ErrMsgDatabaseError {
		t.Errorf("SafeErrorMessage = %q, want %q", got, ErrMsgDatabaseError)
	}
}

func TestFlattenedChainIsStillScrubbed(t *testing.T) {
	// Somewhere a wrapper used %v instead of %w, so errors.As can no longer
	// find the *pq.Error. The rendered-prefix fallback still suppresses it.
	err := fmt.Errorf("failed to list banned ips: %v", newUUIDCastError())

	if errors.As(err, new(*pq.Error)) {
		t.Fatal("test precondition broken: the chain is still unwrappable")
	}
	if detail := SafeErrorDetail(err); detail != "" {
		t.Errorf("SafeErrorDetail = %q, want \"\"", detail)
	}
	if got := SafeErrorMessage(err); got != ErrMsgDatabaseError {
		t.Errorf("SafeErrorMessage = %q, want %q", got, ErrMsgDatabaseError)
	}
	assertNoDriverText(t, "SafeErrorMessage", SafeErrorMessage(err))

	// The status half deliberately does NOT trust the string test, so a
	// flattened chain keeps its 500 rather than being guessed into a 400.
	if _, _, ok := ClientStatusForDBError(err); ok {
		t.Error("ClientStatusForDBError used the string fallback to change a status")
	}
}

func TestApplicationErrorsPassThroughVerbatim(t *testing.T) {
	// nginx -t output and validation messages are the operator's only
	// diagnostic in several UI paths; scrubbing them would be a regression.
	cases := []string{
		"nginx: [emerg] duplicate auth_request directive in /etc/nginx/conf.d/host_1.conf:42",
		"invalid domain name: example..com",
		"acme: error presenting token: dns propagation timed out",
	}
	for _, msg := range cases {
		err := errors.New(msg)
		if got := SafeErrorDetail(err); got != msg {
			t.Errorf("SafeErrorDetail(%q) = %q, want it verbatim", msg, got)
		}
		if got := SafeErrorMessage(err); got != msg {
			t.Errorf("SafeErrorMessage(%q) = %q, want it verbatim", msg, got)
		}
		if _, _, ok := ClientStatusForDBError(err); ok {
			t.Errorf("ClientStatusForDBError(%q) classified a non-driver error", msg)
		}
	}
}

func TestNilErrorIsHandled(t *testing.T) {
	if got := SafeErrorDetail(nil); got != "" {
		t.Errorf("SafeErrorDetail(nil) = %q, want \"\"", got)
	}
	if got := SafeErrorMessage(nil); got != ErrMsgInternalError {
		t.Errorf("SafeErrorMessage(nil) = %q, want %q", got, ErrMsgInternalError)
	}
	if _, _, ok := ClientStatusForDBError(nil); ok {
		t.Error("ClientStatusForDBError(nil) reported a client error")
	}
}

// ─── the 4xx half ───────────────────────────────────────────────────────
//
// The 5xx helpers were gated first, but handlers classify a service error by
// substring and then hand the rendered chain to badRequestError/conflictError,
// which bypassed the gate entirely: a malformed certificate_id in a POST body
// came back as a 400 carrying "pq: invalid input syntax for type uuid …". The
// tests below pin both halves of the answer — the driver text is gone, and the
// wrapper naming the offending field is not.

// measuredLeaks are the exact bodies observed on the pre-fix build.
var measuredLeaks = []struct {
	rendered  string
	keepsWhat string
}{
	{
		`failed to validate certificate_id: failed to get certificate: pq: invalid input syntax for type uuid: "not-a-uuid" (22P02)`,
		"certificate_id",
	},
	{
		`failed to validate access_list_id: pq: invalid input syntax for type uuid: "not-a-uuid" (22P02)`,
		"access_list_id",
	},
}

func TestSafeClientTextDropsTheDriverHalfAndKeepsOurs(t *testing.T) {
	for _, tc := range measuredLeaks {
		got := SafeClientText(tc.rendered)
		assertNoDriverText(t, "SafeClientText", got)
		if !strings.Contains(got, tc.keepsWhat) {
			t.Errorf("SafeClientText(%q) = %q, dropped the field name %q", tc.rendered, got, tc.keepsWhat)
		}
		if !strings.HasSuffix(got, ErrMsgInvalidIdentifier) {
			t.Errorf("SafeClientText(%q) = %q, want it to end in %q", tc.rendered, got, ErrMsgInvalidIdentifier)
		}
	}
}

func TestSafeClientTextNamesTheCauseFromTheSQLState(t *testing.T) {
	// 23505 is not the caller's malformed id, so the replacement must not claim
	// it was — the generic database wording is the honest answer.
	got := SafeClientText(`failed to create user: pq: duplicate key value violates unique constraint "users_username_key" (23505)`)
	assertNoDriverText(t, "SafeClientText", got)
	if strings.Contains(got, ErrMsgInvalidIdentifier) {
		t.Errorf("SafeClientText mislabelled 23505 as a malformed identifier: %q", got)
	}
	if !strings.HasPrefix(got, "failed to create user") {
		t.Errorf("SafeClientText = %q, want our wrapper kept", got)
	}

	// Nothing of ours in front of the driver text: there is no useful half to
	// keep, so the reason stands alone rather than leading with ": ".
	if got := SafeClientText(newUUIDCastError().Error()); got != ErrMsgInvalidIdentifier {
		t.Errorf("SafeClientText(bare driver error) = %q, want %q", got, ErrMsgInvalidIdentifier)
	}
}

func TestSafeClientTextLeavesApplicationMessagesAlone(t *testing.T) {
	// A 400 is where validation messages live, so scrubbing one would cost the
	// operator the only sentence that tells them what to change.
	for _, msg := range []string{
		"invalid domain name: example..com",
		"domain(s) already exist: [app.example.com]",
		"stream_listen_port must be between 1 and 65535",
	} {
		if got := SafeClientText(msg); got != msg {
			t.Errorf("SafeClientText(%q) = %q, want it verbatim", msg, got)
		}
	}
}

// body4xx runs one of the shared helpers and returns the JSON it wrote.
func body4xx(t *testing.T, call func(echo.Context) error) (int, map[string]string) {
	t.Helper()
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
	if err := call(c); err != nil {
		t.Fatalf("helper returned an error: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response body is not a JSON object: %v (%q)", err, rec.Body.String())
	}
	return rec.Code, got
}

func TestSharedClientHelpersScrubWhatTheyAreHanded(t *testing.T) {
	rendered := measuredLeaks[0].rendered

	status, body := body4xx(t, func(c echo.Context) error { return badRequestError(c, rendered) })
	if status != http.StatusBadRequest {
		t.Errorf("badRequestError status = %d, want %d", status, http.StatusBadRequest)
	}
	assertNoDriverText(t, "badRequestError body", body["error"])
	if !strings.Contains(body["error"], "certificate_id") {
		t.Errorf("badRequestError body = %q, dropped the field name", body["error"])
	}

	status, body = body4xx(t, func(c echo.Context) error { return conflictError(c, rendered) })
	if status != http.StatusConflict {
		t.Errorf("conflictError status = %d, want %d", status, http.StatusConflict)
	}
	assertNoDriverText(t, "conflictError body", body["error"])

	_, body = body4xx(t, func(c echo.Context) error { return validationError(c, "certificate_id", rendered) })
	assertNoDriverText(t, "validationError body", body["error"])
}

func TestHTTPWriterHelpersScrubTheirMessageAndDetails(t *testing.T) {
	rendered := measuredLeaks[1].rendered

	rec := httptest.NewRecorder()
	httpJSONError(rec, rendered, http.StatusBadRequest)
	var got ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("httpJSONError body is not JSON: %v", err)
	}
	assertNoDriverText(t, "httpJSONError error", got.Error)
	if !strings.Contains(got.Error, "access_list_id") {
		t.Errorf("httpJSONError error = %q, dropped the field name", got.Error)
	}

	rec = httptest.NewRecorder()
	httpJSONErrorWithDetails(rec, "Failed to delete rule", http.StatusBadRequest, rendered)
	got = ErrorResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("httpJSONErrorWithDetails body is not JSON: %v", err)
	}
	assertNoDriverText(t, "httpJSONErrorWithDetails error", got.Error)
	assertNoDriverText(t, "httpJSONErrorWithDetails details", got.Details)
}
