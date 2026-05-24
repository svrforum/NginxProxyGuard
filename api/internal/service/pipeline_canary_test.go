package service

import "testing"

func TestClassifyCanaryFailure(t *testing.T) {
	cases := []struct {
		name                                            string
		reachable, inFile, pathMatch, accessFlushFresh bool
		want                                            string
	}{
		{"nginx unreachable", false, false, false, false, "nginx_unreachable"},
		{"nginx not writing file", true, false, true, false, "nginx_write"},
		{"tail reading wrong path", true, true, false, false, "path_mismatch"},
		{"tail stalled", true, true, true, false, "tail_stalled"},
		{"db insert failing", true, true, true, true, "db_insert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCanaryFailure(tc.reachable, tc.inFile, tc.pathMatch, tc.accessFlushFresh)
			if got != tc.want {
				t.Errorf("classifyCanaryFailure = %q, want %q", got, tc.want)
			}
		})
	}
}
