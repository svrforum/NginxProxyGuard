package service

import "testing"

func TestIsHiddenContainer(t *testing.T) {
	hidden := []string{"", "npg-db", "npg-api", "npg-proxy", "npg-valkey", "npg_data", "npg-anything"}
	for _, n := range hidden {
		if !isHiddenContainer(n) {
			t.Errorf("isHiddenContainer(%q) = false, want true (should be hidden)", n)
		}
	}
	shown := []string{"npg-ui", "npg_ui", "bebe-app", "nginxproxyguard-api-run-x", "redis"}
	for _, n := range shown {
		if isHiddenContainer(n) {
			t.Errorf("isHiddenContainer(%q) = true, want false (should be shown)", n)
		}
	}
}
