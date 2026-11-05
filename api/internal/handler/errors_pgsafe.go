package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
)

// Postgres SQLSTATE codes. Two are mapped onto a client-facing status, both
// the caller's mistake: invalid_text_representation is a malformed identifier
// reaching a uuid/inet column (#298), string_data_right_truncation a value
// longer than its varchar column, which a field without its own length check
// let through (#353). Every other code deliberately stays a 500 —
// mislabelling one of our own bugs as the caller's fault is worse than a
// vague 500.
const (
	sqlStateInvalidTextRepresentation = database.SQLStateInvalidTextRepresentation
	sqlStateStringDataRightTruncation = database.SQLStateStringDataRightTruncation
)

// ErrMsgInvalidIdentifier is returned when a path/body identifier could not be
// parsed by Postgres (e.g. "not-a-uuid" reaching a uuid column).
const ErrMsgInvalidIdentifier = database.MsgInvalidIdentifier

// ErrMsgValueTooLong is returned when Postgres refused a value longer than its
// column allows.
const ErrMsgValueTooLong = database.MsgValueTooLong

// driverTextPrefix is what lib/pq puts in front of every server error it
// renders: Error() returns "pq: <message>", or "pq: <message> (<SQLSTATE>)"
// once the code is known. It is therefore an exact boundary between the text
// we wrote and the text the driver wrote.
const driverTextPrefix = database.DriverTextPrefix

// isDriverError reports whether a Postgres driver error sits anywhere in the
// error chain. lib/pq renders "pq: <message> (<SQLSTATE>)" and, when the driver
// kept the statement, appends " at position <line>:<col>" — so the rendered
// string hands any authenticated caller the SQLSTATE, the column type and the
// geometry of our SQL. errors.As is the primary test (repositories wrap with
// %w); the strings.Contains fallback catches a chain that was flattened with
// %v somewhere and can no longer be unwrapped.
func isDriverError(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return true
	}
	return strings.Contains(err.Error(), driverTextPrefix)
}

// SafeErrorDetail is what goes into ErrorResponse.Details. It returns "" when a
// driver error is present so that `json:"details,omitempty"` drops the field
// entirely. The caller has already logged the full error; this only decides
// what crosses the wire. Application errors (nginx -t output, validation,
// ACME failures) are returned verbatim.
func SafeErrorDetail(err error) string {
	if err == nil || isDriverError(err) {
		return ""
	}
	return err.Error()
}

// SafeErrorMessage is what goes into a bare {"error": ...} field, where an
// empty string would leave the client with nothing to show.
func SafeErrorMessage(err error) string {
	if err == nil {
		return ErrMsgInternalError
	}
	if isDriverError(err) {
		return ErrMsgDatabaseError
	}
	return err.Error()
}

// SafeClientText scrubs a message that is about to be sent at a 4xx status.
//
// The 5xx helpers can drop a driver-tainted string wholesale, because none of
// it was ours to begin with. A 4xx message is different. Handlers classify a
// service error by substring ("invalid", "already exist") and hand the rendered
// chain straight to badRequestError/conflictError, so the string is
// "<our wrapper>: <our wrapper>: pq: <driver text>". The wrappers name the
// field that was rejected — "failed to validate certificate_id" is the only
// thing telling the caller what to fix — so blanking them would answer a 400
// with less information than the status line already carries.
//
// The string is therefore cut at the driver boundary and the driver half is
// replaced with a fixed reason. The reason comes from the SQLSTATE lib/pq
// renders inside its own text, so a malformed identifier says so and anything
// else falls back to the generic database wording rather than mislabelling the
// cause. Messages with no driver text in them are returned untouched. (#298)
// The scrub itself lives in internal/database, because a response is not the
// only way driver text escapes: several tables persist an error string and
// serve it back. One definition keeps the wire and the stored copy in step.
func SafeClientText(message string) string {
	return database.ScrubDriverText(message)
}

// scrubbedClientText is what the shared 4xx helpers actually call. The 5xx
// helpers log before they classify, so the full driver text survives in the
// container log; the 4xx helpers take a string and never logged anything,
// which would have made the scrub the point where the SQLSTATE stopped
// existing at all. Logging only when the text actually changed keeps ordinary
// validation 400s — the overwhelming majority — silent.
func scrubbedClientText(message string) string {
	safe := SafeClientText(message)
	if safe != message {
		log.Printf("[ERROR] client error scrubbed before send: %s", message)
	}
	return safe
}

// ClientStatusForDBError maps a driver error onto a caller-facing status when
// the SQLSTATE proves the request itself was malformed. ok=false means "leave
// it a 500". Only errors.As is consulted here — never the string fallback —
// so a status is never changed on the strength of a substring match.
func ClientStatusForDBError(err error) (int, string, bool) {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return 0, "", false
	}
	switch string(pqErr.Code) {
	case sqlStateInvalidTextRepresentation:
		return http.StatusBadRequest, ErrMsgInvalidIdentifier, true
	case sqlStateStringDataRightTruncation:
		return http.StatusBadRequest, ErrMsgValueTooLong, true
	}
	return 0, "", false
}

// directInternalError is the gate for the handlers that build their own 500
// body instead of calling internalError/databaseError. It keeps their existing
// bare {"error": ...} shape — so no client contract changes — while adding the
// same two properties the shared helpers now have: a malformed identifier is
// answered with 400, and driver text never reaches the body. A reload nginx
// refused is answered as the shared helpers answer it: 409 with the
// ErrorResponse body (error, details, code).
func directInternalError(c echo.Context, err error) error {
	if status, body, ok := reloadRejectedResponse(err); ok {
		return c.JSON(status, body)
	}
	if status, msg, ok := ClientStatusForDBError(err); ok {
		return c.JSON(status, map[string]string{"error": msg})
	}
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": SafeErrorMessage(err)})
}
