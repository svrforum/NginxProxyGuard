package service

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.28.4", "2.28.4", 0},
		{"2.28.3", "2.28.4", -1}, // current < latest → update available
		{"2.28.4", "2.28.3", 1},  // current > latest (dev ahead) → no update
		{"2.28.4", "2.29.0", -1},
		{"2.9.0", "2.28.0", -1},  // numeric, not lexical (9 < 28)
		{"v2.28.4", "2.28.4", 0}, // leading v ignored
		{"2.28", "2.28.1", -1},   // missing patch counts as 0
		{"2.28.1", "2.28", 1},
		{"3.0.0", "2.99.99", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// updateAvailable mirrors the handler's rule (current < latest).
func TestUpdateAvailableRule(t *testing.T) {
	if compareVersions("2.28.3", "2.28.4") >= 0 {
		t.Fatal("2.28.3 should be considered behind 2.28.4")
	}
	if compareVersions("2.28.4", "2.28.4") < 0 {
		t.Fatal("equal versions must not report an update")
	}
}
