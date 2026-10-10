package model

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The lists only word the 400; the IsValid* maps decide. A value added to one
// and not the other would either be refused with a message that lists it, or
// accepted while the message leaves it out.
func TestLogEnumListsMatchTheirGuards(t *testing.T) {
	for _, tc := range []struct {
		name  string
		list  []string
		valid func(string) bool
		size  int
	}{
		{"LogTypes", LogTypes, IsValidLogType, len(validLogTypes)},
		{"LogSeverities", LogSeverities, IsValidSeverity, len(validSeverities)},
		{"BlockReasons", BlockReasons, IsValidBlockReason, len(validBlockReasons)},
	} {
		seen := map[string]bool{}
		for _, v := range tc.list {
			if !tc.valid(v) {
				t.Errorf("%s lists %q, which its guard refuses", tc.name, v)
			}
			if seen[v] {
				t.Errorf("%s lists %q twice", tc.name, v)
			}
			seen[v] = true
		}
		if len(seen) != tc.size {
			t.Errorf("%s has %d values, its guard accepts %d", tc.name, len(seen), tc.size)
		}
	}
}

// Everything the logs table stores must still pass: a check stricter than the
// table would turn entries that used to be stored into 400s.
func TestValidateCreateLogRequest_AcceptsWhatTheTableStores(t *testing.T) {
	reqs := []CreateLogRequest{
		{LogType: LogTypeAccess, StatusCode: 100},
		{LogType: LogTypeAccess, StatusCode: 599},
		{LogType: LogTypeAccess, StatusCode: 0}, // no status, stored as NULL
		{LogType: LogTypeAccess, ClientIP: "192.0.2.1"},
		{LogType: LogTypeAccess, ClientIP: "2001:db8::1"},
		{LogType: LogTypeAccess, ClientIP: "::ffff:192.0.2.1"},
		{LogType: LogTypeAccess, ProxyHostID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{LogType: LogTypeAccess, ProxyHostID: "6BA7B810-9DAD-11D1-80B4-00C04FD430C8"},
		{LogType: LogTypeAccess, GeoCountryCode: "KR"},
		{LogType: LogTypeAccess, GeoCountryCode: "한국"}, // varchar counts characters
		{LogType: LogTypeModSec, ExploitRule: strings.Repeat("규", 50)},
	}
	for _, v := range LogTypes {
		reqs = append(reqs, CreateLogRequest{LogType: LogType(v)})
	}
	for _, v := range LogSeverities {
		reqs = append(reqs, CreateLogRequest{LogType: LogTypeError, Severity: LogSeverity(v)})
	}
	for _, v := range BlockReasons {
		reqs = append(reqs, CreateLogRequest{LogType: LogTypeAccess, BlockReason: BlockReason(v)})
	}
	for _, r := range reqs {
		if err := ValidateCreateLogRequest(&r); err != nil {
			t.Errorf("%+v refused: %v", r, err)
		}
	}
}

// No text column takes NUL, and JSON can carry one ("\u0000"). Every string
// field of the request — including any added later — must be refused with its
// JSON name, whichever check catches it.
func TestValidateCreateLogRequest_RefusesNULInEveryStringField(t *testing.T) {
	typ := reflect.TypeOf(CreateLogRequest{})
	checked := 0
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.Type.Kind() != reflect.String || name == "" || name == "-" {
			continue
		}
		req := CreateLogRequest{LogType: LogTypeAccess}
		reflect.ValueOf(&req).Elem().Field(i).SetString("a\x00b")
		err := ValidateCreateLogRequest(&req)
		if err == nil {
			t.Errorf("%s with a NUL character was accepted", name)
			continue
		}
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: error does not wrap ErrInvalidInput: %v", name, err)
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s: error does not name the field: %v", name, err)
		}
		checked++
	}
	if checked < 25 {
		t.Fatalf("only %d string fields checked", checked)
	}
}
