package service

import "testing"

func TestPickContainerIP(t *testing.T) {
	containers := []DockerContainerInfo{
		{Name: "other", Networks: []DockerContainerNetwork{{Name: "bridge", IPAddress: "172.18.0.9"}}},
		{Name: "myapp", Networks: []DockerContainerNetwork{
			{Name: "bridge", IPAddress: ""},
			{Name: "secondary", IPAddress: "172.18.0.5"},
		}},
	}

	// Legacy path: empty network → first non-empty IP (back-compat).
	ip, err := pickContainerIP(containers, "myapp", "")
	if err != nil || ip != "172.18.0.5" {
		t.Fatalf("legacy empty-network: got (%q,%v), want (172.18.0.5,nil)", ip, err)
	}

	// Missing container → error regardless of network.
	if _, err := pickContainerIP(containers, "ghost", ""); err == nil {
		t.Fatalf("expected error for missing container")
	}
}

// TestPickContainerIPMultiNetwork covers the network-aware behavior added for
// Issue #151: multi-network containers must resolve to the IP of the network
// the user picked, not to whatever Docker happens to list first.
func TestPickContainerIPMultiNetwork(t *testing.T) {
	containers := []DockerContainerInfo{
		{Name: "immich_server_a", Networks: []DockerContainerNetwork{
			{Name: "default", IPAddress: "172.19.0.18"},
			{Name: "bebe", IPAddress: "172.24.0.4"},
		}},
	}

	// Network specified + matches → that network's IP.
	ip, err := pickContainerIP(containers, "immich_server_a", "bebe")
	if err != nil || ip != "172.24.0.4" {
		t.Fatalf("network match: got (%q,%v), want (172.24.0.4,nil)", ip, err)
	}
	ip, err = pickContainerIP(containers, "immich_server_a", "default")
	if err != nil || ip != "172.19.0.18" {
		t.Fatalf("network match (default): got (%q,%v), want (172.19.0.18,nil)", ip, err)
	}

	// Network specified + no match → error (caller must SKIP, not fall back).
	if _, err := pickContainerIP(containers, "immich_server_a", "ghost-net"); err == nil {
		t.Fatalf("expected error when network is not attached")
	}

	// Empty network → legacy first-non-empty-IP behavior.
	ip, err = pickContainerIP(containers, "immich_server_a", "")
	if err != nil || ip != "172.19.0.18" {
		t.Fatalf("empty network legacy: got (%q,%v), want (172.19.0.18,nil)", ip, err)
	}
}
