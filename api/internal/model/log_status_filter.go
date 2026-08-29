package model

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Status-code filtering accepts two token shapes so the log viewer can offer
// both "show me exactly 499" and "show me every 4xx":
//
//	status_codes=499&status_codes=444      explicit codes
//	status_classes=4xx&status_classes=5xx  a whole class
//
// Classes are expanded here, server-side, into explicit code lists rather than
// rendered as a BETWEEN. status_code is neither a segmentby nor an orderby
// column on the logs hypertable, so on compressed chunks the only thing that
// can prune before decompression is the bloom sparse index, and that only
// applies to equality / IN. A range predicate compiles to a post-decompression
// filter instead — the shape that looks fine and quietly reads every chunk.
//
// A class expands to the full N00..N99 rather than to the registered codes
// only. nginx logs 444 and 494-499, Cloudflare adds 52x, and an upstream can
// return whatever it likes; curating the list would silently drop exactly the
// unusual codes somebody is filtering for.
const (
	// maxStatusCodeTokens bounds the explicit codes accepted per parameter.
	// It applies to the INPUT only — see the note in ParseStatusFilter for why
	// the expanded set must not be capped.
	maxStatusCodeTokens = 100
	// maxStatusClassTokens is generous: only 1xx-5xx exist.
	maxStatusClassTokens = 8

	statusCodeMin = 100
	statusCodeMax = 599
)

// ExpandStatusClass turns a class token ("4xx", "4XX") into its code range.
func ExpandStatusClass(token string) ([]int, error) {
	t := strings.ToLower(strings.TrimSpace(token))
	if len(t) != 3 || !strings.HasSuffix(t, "xx") {
		return nil, fmt.Errorf("%w: invalid status class %q: expected one of 1xx, 2xx, 3xx, 4xx, 5xx", ErrInvalidInput, token)
	}
	lead := int(t[0] - '0')
	if lead < 1 || lead > 5 {
		return nil, fmt.Errorf("%w: invalid status class %q: expected one of 1xx, 2xx, 3xx, 4xx, 5xx", ErrInvalidInput, token)
	}
	codes := make([]int, 0, 100)
	for c := lead * 100; c < (lead+1)*100; c++ {
		codes = append(codes, c)
	}
	return codes, nil
}

// ParseStatusFilter merges explicit status codes and class tokens into one
// sorted, de-duplicated list. Both inputs are optional; an empty result means
// "no status filter", not "match nothing".
//
// Invalid tokens are rejected rather than dropped. A silently ignored "4o1"
// produces an unfiltered view that looks like a filtered one, which is the
// same failure mode that made fail2ban's fail codes look broken.
func ParseStatusFilter(codeTokens, classTokens []string) ([]int, error) {
	if len(codeTokens) > maxStatusCodeTokens {
		return nil, fmt.Errorf("%w: too many status codes (max %d)", ErrInvalidInput, maxStatusCodeTokens)
	}
	if len(classTokens) > maxStatusClassTokens {
		return nil, fmt.Errorf("%w: too many status classes (max %d)", ErrInvalidInput, maxStatusClassTokens)
	}

	// The expanded set needs no cap of its own: every entry is a distinct code
	// in [100,599], so it can never exceed 500 however many tokens arrive. What
	// must NOT happen is capping it at the input limit — that would silently
	// truncate "4xx and 5xx" to 4xx with the 5xx chip still lit.
	seen := make(map[int]struct{}, statusCodeMax-statusCodeMin+1)
	add := func(code int) {
		seen[code] = struct{}{}
	}

	for _, raw := range codeTokens {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		code, err := strconv.Atoi(token)
		if err != nil || code < statusCodeMin || code > statusCodeMax {
			return nil, fmt.Errorf("%w: invalid status code %q: expected a number between %d and %d", ErrInvalidInput, token, statusCodeMin, statusCodeMax)
		}
		add(code)
	}

	for _, raw := range classTokens {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		codes, err := ExpandStatusClass(raw)
		if err != nil {
			return nil, err
		}
		for _, c := range codes {
			add(c)
		}
	}

	if len(seen) == 0 {
		return nil, nil
	}

	out := make([]int, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Ints(out)
	return out, nil
}
