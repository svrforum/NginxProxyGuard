package database

import "strings"

// Postgres driver text, and what replaces it.
//
// The handler layer already refuses to put lib/pq's rendered text into an HTTP
// response (#298). "pq: <message> (<SQLSTATE>)" — plus " at position <line>:<col>"
// when the driver kept the statement — hands any authenticated caller the
// SQLSTATE, the column type and the geometry of our SQL.
//
// A response is not the only way out, though. Several tables persist an error
// string and serve it back later: backups.error_message, ddns_records.message,
// proxy_hosts.config_error. Those writes store whatever err.Error() rendered,
// so a failure that was itself a database error — the most likely kind in a
// backup or a config sync — parks the driver text in a row, and every later
// read replays it long after the request that produced it is gone. Scrubbing
// only on the way out of a handler never reaches those.
//
// This file is the single definition of where the driver's text starts and what
// stands in for it; handler.SafeClientText delegates here. It lives in
// `database` rather than a helper package because that is the layer that owns
// the driver, and because being a leaf import lets the repository layer — where
// the persisting writes happen — call it without a cycle.
const (
	// DriverTextPrefix is what lib/pq puts in front of every server error it
	// renders, and is therefore an exact boundary between the text we wrote and
	// the text the driver wrote.
	DriverTextPrefix = "pq: "

	// MsgDatabaseError, MsgInvalidIdentifier and MsgValueTooLong are the
	// replacements. The last two are used when the SQLSTATE lib/pq rendered into
	// its own text proves the value was at fault, so a bad identifier or an
	// over-long value says so instead of being flattened into a generic database
	// failure.
	MsgDatabaseError     = "A database error occurred"
	MsgInvalidIdentifier = "Invalid identifier format"
	MsgValueTooLong      = "A value is longer than its field allows"

	// SQLStateInvalidTextRepresentation (22P02) is raised when a value cannot be
	// parsed into its column's type — "not-a-uuid" reaching a uuid column, or a
	// malformed address reaching inet.
	SQLStateInvalidTextRepresentation = "22P02"

	// SQLStateStringDataRightTruncation (22001) is raised when a value is longer
	// than its varchar column allows — a length nothing checked first (#353).
	SQLStateStringDataRightTruncation = "22001"
)

// ScrubDriverText cuts a message at the driver boundary and replaces the
// driver's half with a fixed reason, keeping ours.
//
// Keeping the prefix matters: these strings are built by wrapping, so what
// arrives is "<our wrapper>: <our wrapper>: pq: <driver text>". The wrappers
// name what was being attempted — "failed to render config", "backup upload" —
// and for someone reading a failed row days later that is the whole value of
// the field. Blanking the string would replace a locatable failure with a shrug.
//
// A message with no driver text in it is returned untouched, so this is safe to
// call unconditionally on any path, whatever the error turns out to be.
func ScrubDriverText(message string) string {
	i := strings.Index(message, DriverTextPrefix)
	if i < 0 {
		return message
	}

	reason := MsgDatabaseError
	if strings.Contains(message[i:], "("+SQLStateInvalidTextRepresentation+")") {
		reason = MsgInvalidIdentifier
	} else if strings.Contains(message[i:], "("+SQLStateStringDataRightTruncation+")") {
		reason = MsgValueTooLong
	}

	prefix := strings.TrimRight(message[:i], " \t:,-")
	if prefix == "" {
		return reason
	}
	return prefix + ": " + reason
}
