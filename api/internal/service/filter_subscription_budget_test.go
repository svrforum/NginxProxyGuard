package service

import "testing"

// One list may now use the whole total (#361), and the room left for a
// subscription can be below zero: creating one did not count the others
// against the total before, and refreshing next to them sliced with a
// negative bound and panicked.
func TestEntryBudget(t *testing.T) {
	cases := []struct {
		other, want int
	}{
		{0, 100000},      // a 188,000-entry list keeps 100,000
		{90000, 10000},   // what the total leaves
		{100000, 0},      // no room
		{124999, -24999}, // the others already over the total
	}
	for _, c := range cases {
		if got := entryBudget(c.other); got != c.want {
			t.Errorf("entryBudget(%d) = %d, want %d", c.other, got, c.want)
		}
	}
}
