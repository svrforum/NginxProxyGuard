package model

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Columns of logs_partitioned narrower than the text a request can carry.
const (
	logGeoCountryCodeMaxLen = 2  // geo_country_code varchar(2)
	logExploitRuleMaxLen    = 50 // exploit_rule varchar(50)
)

// ValidateCreateLogRequest rejects a manual log entry (POST /logs) holding a
// value the logs table would refuse. Postgres used to refuse it instead, and
// the handler answered 500 "Failed to create log" for what was the caller's
// mistake (#325): log_type, severity and block_reason are enums, client_ip and
// proxy_host_id are cast to inet and uuid, status_code is an integer column,
// geo_country_code and exploit_rule are varchar(2) and varchar(50), and no
// text column takes a NUL character.
//
// Every error wraps ErrInvalidInput and names the field; an enum error also
// lists the accepted values.
func ValidateCreateLogRequest(req *CreateLogRequest) error {
	if req.LogType == "" {
		return fmt.Errorf("%w: log_type is required: must be one of %s", ErrInvalidInput, strings.Join(LogTypes, ", "))
	}
	if err := logEnumOrError("log_type", string(req.LogType), IsValidLogType, LogTypes); err != nil {
		return err
	}
	// Both optional: an empty severity is stored as NULL, an empty
	// block_reason as "none".
	if req.Severity != "" {
		if err := logEnumOrError("severity", string(req.Severity), IsValidSeverity, LogSeverities); err != nil {
			return err
		}
	}
	if req.BlockReason != "" {
		if err := logEnumOrError("block_reason", string(req.BlockReason), IsValidBlockReason, BlockReasons); err != nil {
			return err
		}
	}

	// One address. inet would also take a range such as "192.0.2.0/24", which
	// reads back as an empty client_ip.
	if req.ClientIP != "" && net.ParseIP(req.ClientIP) == nil {
		return fmt.Errorf("%w: invalid client_ip %q: must be an IPv4 or IPv6 address", ErrInvalidInput, req.ClientIP)
	}
	// The 36-character form only: uuid.Parse also takes "urn:uuid:...", which
	// the uuid column refuses.
	if req.ProxyHostID != "" {
		if _, err := uuid.Parse(req.ProxyHostID); err != nil || len(req.ProxyHostID) != 36 {
			return fmt.Errorf("%w: invalid proxy_host_id %q: must be a UUID in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", ErrInvalidInput, req.ProxyHostID)
		}
	}
	// 0 means no status and is stored as NULL. Otherwise a real HTTP status
	// (RFC 9110: 100-599, the range the status_codes filter takes), which also
	// keeps the value inside the integer column.
	if req.StatusCode != 0 && (req.StatusCode < statusCodeMin || req.StatusCode > statusCodeMax) {
		return fmt.Errorf("%w: invalid status_code %d: must be between %d and %d", ErrInvalidInput, req.StatusCode, statusCodeMin, statusCodeMax)
	}
	// varchar(n) counts characters, not bytes.
	if utf8.RuneCountInString(req.GeoCountryCode) > logGeoCountryCodeMaxLen {
		return fmt.Errorf("%w: invalid geo_country_code %q: must be at most %d characters", ErrInvalidInput, req.GeoCountryCode, logGeoCountryCodeMaxLen)
	}
	if utf8.RuneCountInString(req.ExploitRule) > logExploitRuleMaxLen {
		return fmt.Errorf("%w: invalid exploit_rule: must be at most %d characters", ErrInvalidInput, logExploitRuleMaxLen)
	}

	return rejectNULInLogText(req)
}

// logEnumOrError words a rejection as oneOfOrError does, but decides with the
// IsValid* guard the log filters use.
func logEnumOrError(field, value string, valid func(string) bool, accepted []string) error {
	if valid(value) {
		return nil
	}
	return fmt.Errorf("%w: invalid %s %q: must be one of %s", ErrInvalidInput, field, value, strings.Join(accepted, ", "))
}

// rejectNULInLogText refuses a NUL character in any string field: JSON can
// carry one as "\u0000", and a Postgres text column cannot store it. Walking
// the struct keeps a field added later covered.
func rejectNULInLogText(req *CreateLogRequest) error {
	v := reflect.ValueOf(req).Elem()
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.String && strings.ContainsRune(f.String(), 0) {
			name, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("json"), ",")
			return fmt.Errorf("%w: invalid %s: must not contain a NUL character", ErrInvalidInput, name)
		}
	}
	return nil
}
