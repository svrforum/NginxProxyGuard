package model

import "testing"

// ValidateScope is the only thing between an operator-supplied string and a
// generated ModSecurity directive, and it had no test. A scope_value reaches
// the config file verbatim, so a quote or a newline would let a caller append
// their own directives — "SecRuleEngine Off" is one line away. (#231, #286)
func TestValidateScope(t *testing.T) {
	cases := []struct {
		name      string
		in        WAFRuleExclusion
		wantErr   bool
		wantType  string
		wantValue string
	}{
		// Normalisation: an omitted scope is the host-wide behaviour every
		// client got before scoped exclusions existed.
		{name: "empty normalises to host", in: WAFRuleExclusion{}, wantType: WAFScopeHost, wantValue: ""},
		{name: "host clears any value", in: WAFRuleExclusion{ScopeType: WAFScopeHost, ScopeValue: "/ignored"}, wantType: WAFScopeHost, wantValue: ""},

		{name: "uri path", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/api/a"}, wantType: WAFScopeURI, wantValue: "/api/a"},
		{name: "uri trims surrounding space", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "  /api/a  "}, wantType: WAFScopeURI, wantValue: "/api/a"},
		{name: "param name", in: WAFRuleExclusion{ScopeType: WAFScopeParam, ScopeValue: "token"}, wantType: WAFScopeParam, wantValue: "token"},
		{name: "param with brackets", in: WAFRuleExclusion{ScopeType: WAFScopeParam, ScopeValue: "user[id]"}, wantType: WAFScopeParam, wantValue: "user[id]"},

		{name: "unknown scope type", in: WAFRuleExclusion{ScopeType: "path"}, wantErr: true},
		{name: "uri requires a value", in: WAFRuleExclusion{ScopeType: WAFScopeURI}, wantErr: true},
		{name: "uri must be absolute", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "api/a"}, wantErr: true},
		// "/" prefixes every request, so it is a host-wide disable wearing a
		// scope. Normalised rather than rejected: v2.37.0-v2.53.0 stored this
		// value, and the log viewer prefills it for a root-path block. (#286)
		{name: "uri bare slash normalises to host", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/"}, wantType: WAFScopeHost, wantValue: ""},
		{name: "uri bare slash with spaces normalises too", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "  /  "}, wantType: WAFScopeHost, wantValue: ""},
		{name: "param rejects a path", in: WAFRuleExclusion{ScopeType: WAFScopeParam, ScopeValue: "/api/a"}, wantErr: true},

		// Injection surface: every one of these would break out of the quoted
		// directive or start a new one.
		{name: "rejects double quote", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: `/a"b`}, wantErr: true},
		{name: "rejects single quote", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/a'b"}, wantErr: true},
		{name: "rejects backslash", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: `/a\b`}, wantErr: true},
		{name: "rejects semicolon", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/a;b"}, wantErr: true},
		{name: "rejects braces", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/a{b}"}, wantErr: true},
		{name: "rejects newline", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/a\nSecRuleEngine Off"}, wantErr: true},
		{name: "rejects space", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/a b"}, wantErr: true},
		{name: "rejects non-ascii", in: WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: "/경로"}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.in
			err := e.ValidateScope()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got scope_type=%q scope_value=%q", e.ScopeType, e.ScopeValue)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.ScopeType != tc.wantType {
				t.Errorf("scope_type = %q, want %q", e.ScopeType, tc.wantType)
			}
			if e.ScopeValue != tc.wantValue {
				t.Errorf("scope_value = %q, want %q", e.ScopeValue, tc.wantValue)
			}
		})
	}
}

// A value that is too long would still be syntactically fine in the directive,
// so the bound is its own case.
func TestValidateScopeLengthBound(t *testing.T) {
	long := "/" + string(make([]byte, maxScopeValue))
	for i := 1; i < len(long); i++ {
		long = long[:i] + "a" + long[i+1:]
	}
	e := WAFRuleExclusion{ScopeType: WAFScopeURI, ScopeValue: long}
	if err := e.ValidateScope(); err == nil {
		t.Fatalf("expected a length error for a %d-character value", len(long))
	}
}
