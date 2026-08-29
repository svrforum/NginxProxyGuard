package model

import (
	"errors"
	"testing"
)

func TestExpandStatusClass(t *testing.T) {
	codes, err := ExpandStatusClass("4xx")
	if err != nil {
		t.Fatalf("4xx: unexpected error: %v", err)
	}
	if len(codes) != 100 || codes[0] != 400 || codes[99] != 499 {
		t.Fatalf("4xx expanded to %d codes (%d..%d), want 100 (400..499)", len(codes), codes[0], codes[len(codes)-1])
	}
	// nginx-only codes must survive the expansion — curating to registered
	// codes would drop exactly the ones an operator hunts for.
	for _, want := range []int{444, 499} {
		found := false
		for _, c := range codes {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("4xx expansion is missing %d", want)
		}
	}

	if _, err := ExpandStatusClass("4XX"); err != nil {
		t.Errorf("uppercase class should be accepted: %v", err)
	}
	for _, bad := range []string{"6xx", "0xx", "xx", "4x", "4xxx", "abc", ""} {
		if _, err := ExpandStatusClass(bad); err == nil {
			t.Errorf("class %q should be rejected", bad)
		} else if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("class %q: error does not wrap ErrInvalidInput: %v", bad, err)
		}
	}
}

func TestParseStatusFilter(t *testing.T) {
	if got, err := ParseStatusFilter(nil, nil); err != nil || got != nil {
		t.Fatalf("empty input: got %v, %v; want nil, nil", got, err)
	}

	got, err := ParseStatusFilter([]string{"499", "444", "499"}, nil)
	if err != nil {
		t.Fatalf("explicit codes: %v", err)
	}
	if len(got) != 2 || got[0] != 444 || got[1] != 499 {
		t.Fatalf("explicit codes: got %v, want [444 499] sorted and deduped", got)
	}

	// The regression this guards: ticking two classes must not silently
	// truncate to one. 4xx+5xx is 200 codes; a cap applied to the expansion
	// would drop every 5xx and show a filtered view with no error.
	got, err = ParseStatusFilter(nil, []string{"4xx", "5xx"})
	if err != nil {
		t.Fatalf("two classes: %v", err)
	}
	if len(got) != 200 {
		t.Fatalf("4xx+5xx expanded to %d codes, want 200", len(got))
	}
	if got[0] != 400 || got[199] != 599 {
		t.Fatalf("4xx+5xx range is %d..%d, want 400..599", got[0], got[199])
	}

	// A class and an overlapping explicit code collapse to one entry.
	got, err = ParseStatusFilter([]string{"404"}, []string{"4xx"})
	if err != nil {
		t.Fatalf("class + overlapping code: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("4xx + 404 gave %d codes, want 100 (deduped)", len(got))
	}

	// All five classes still fit under the expanded bound.
	if _, err := ParseStatusFilter(nil, []string{"1xx", "2xx", "3xx", "4xx", "5xx"}); err != nil {
		t.Fatalf("all five classes should be accepted: %v", err)
	}

	for _, bad := range [][]string{{"4o1"}, {"401;403"}, {"99"}, {"600"}, {"-1"}, {"4xx"}} {
		if _, err := ParseStatusFilter(bad, nil); err == nil {
			t.Errorf("codes %v should be rejected", bad)
		} else if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("codes %v: error does not wrap ErrInvalidInput: %v", bad, err)
		}
	}

	// Blank tokens are ignored rather than rejected: an empty query parameter
	// is what a cleared UI field sends.
	if got, err := ParseStatusFilter([]string{"", " "}, []string{""}); err != nil || got != nil {
		t.Fatalf("blank tokens: got %v, %v; want nil, nil", got, err)
	}

	tooMany := make([]string, maxStatusCodeTokens+1)
	for i := range tooMany {
		tooMany[i] = "404"
	}
	if _, err := ParseStatusFilter(tooMany, nil); err == nil {
		t.Error("over-cap code list should be rejected")
	}
}
