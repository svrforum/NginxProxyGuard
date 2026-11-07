package model

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// The rules are stored trimmed, each entry once, a status class in lower
// case, a method in upper case and a path decoded.
func TestNormalizeHostLogRules(t *testing.T) {
	rules, err := NormalizeHostLogRules(UpdateHostLogRulesRequest{
		SkipAll:      true,
		SkipStatuses: []string{" 207 ", "3XX", "207"},
		SkipMethods:  []string{"propfind", " OPTIONS", "PROPFIND", "VERSION-CONTROL"},
		SkipPaths:    []string{"/remote.php/dav/", " /files/My%20Docs/", "/remote.php/dav/"},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := HostLogRules{
		SkipAll:      true,
		SkipStatuses: []string{"207", "3xx"},
		SkipMethods:  []string{"PROPFIND", "OPTIONS", "VERSION-CONTROL"},
		SkipPaths:    []string{"/remote.php/dav/", "/files/My Docs/"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("rules = %+v, want %+v", rules, want)
	}

	empty, err := NormalizeHostLogRules(UpdateHostLogRulesRequest{})
	if err != nil || !empty.IsEmpty() || empty.SkipStatuses == nil {
		t.Errorf("no rules = %+v, %v; want empty, non-nil lists", empty, err)
	}
}

func TestNormalizeHostLogRulesRefuses(t *testing.T) {
	for name, req := range map[string]UpdateHostLogRulesRequest{
		"a status out of range":  {SkipStatuses: []string{"600"}},
		"a status of two digits": {SkipStatuses: []string{"20"}},
		"a class of x only":      {SkipStatuses: []string{"xxx"}},
		"a method with a space":  {SkipMethods: []string{"GET POST"}},
		"an empty method":        {SkipMethods: []string{" "}},
		"a relative path":        {SkipPaths: []string{"remote.php"}},
		"a path with a query":    {SkipPaths: []string{"/a?b=1"}},
		"a dot segment":          {SkipPaths: []string{"/a/../b"}},
		"a double slash":         {SkipPaths: []string{"/a//b"}},
		"a backslash":            {SkipPaths: []string{`/a\b`}},
		"a bad escape":           {SkipPaths: []string{"/a%zz"}},
		"a control character":    {SkipPaths: []string{"/a%0ab"}},
	} {
		if _, err := NormalizeHostLogRules(req); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}

	var many []string
	for i := 0; i <= MaxHostLogRuleEntries; i++ {
		many = append(many, fmt.Sprintf("/p%d", i))
	}
	if _, err := NormalizeHostLogRules(UpdateHostLogRulesRequest{SkipPaths: many}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("%d paths: err = %v, want ErrInvalidInput", len(many), err)
	}
}
