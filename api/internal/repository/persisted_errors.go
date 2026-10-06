package repository

import (
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/redact"
)

// Scrubbing driver text on the way *into* a column, not just on the way out of
// a handler.
//
// #298 stopped lib/pq's rendered text — "pq: <message> (<SQLSTATE>) at position
// <line>:<col>" — from reaching an HTTP response. That gate sits in the handler
// layer, so it only covers text that is being returned right now.
//
// Four columns escape it by persisting the string instead: proxy_hosts.config_error,
// backups.error_message, ddns_records.last_error and geoip_update_history.error_message.
// Each is written from a bare err.Error() by a background path — a config sync, a
// scheduled backup, a DDNS refresh, a GeoIP update — where a database failure is
// among the likelier outcomes. The row then survives the request, and every later
// read of the list replays the SQLSTATE and the shape of our SQL to whoever opens
// that page. A response-layer scrub can never reach those, because by then the
// value is data, not an error.
//
// So the scrub is applied at the write. These helpers exist to make that one line
// per call site and to keep all four pointing at the same definition
// (database.ScrubDriverText), which is also what handler.SafeClientText uses.
//
// Both are no-ops for the overwhelmingly common case: an nginx -t failure, an ACME
// rejection or a provider's HTTP error contains no "pq: " and is stored verbatim.
//
// The same write also cuts out the credentials redact.Shapes recognises in a URL —
// a token= parameter, a Telegram bot path, a Discord or Slack webhook path. The
// code that builds these messages redacts the credentials it holds at the source;
// this is the backstop for a wording or a path nobody listed, so a credential that
// slips through is still not replayed to every reader of the column. Notification
// columns are not written through here: the dispatcher redacts a delivery error by
// value before it is stored (service.redactDeliveryError).

// persistedErrorText prepares an error string for a column that will be read
// back and displayed.
func persistedErrorText(message string) string {
	return redact.Shapes(database.ScrubDriverText(message))
}

// persistedErrorPtr is the nullable form. nil stays nil — "no error" must not
// become the empty string, which several read paths render as a blank failure
// rather than as success.
func persistedErrorPtr(message *string) *string {
	if message == nil {
		return nil
	}
	scrubbed := persistedErrorText(*message)
	return &scrubbed
}
