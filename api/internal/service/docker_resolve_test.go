package service

import "testing"

func TestPickContainerIP(t *testing.T) {
	containers := []DockerContainerInfo{
		{Name: "other", Networks: []DockerContainerNetwork{{IPAddress: "172.18.0.9"}}},
		{Name: "myapp", Networks: []DockerContainerNetwork{{IPAddress: ""}, {IPAddress: "172.18.0.5"}}},
	}
	ip, err := pickContainerIP(containers, "myapp")
	if err != nil || ip != "172.18.0.5" {
		t.Fatalf("got (%q,%v), want (172.18.0.5,nil)", ip, err)
	}
	if _, err := pickContainerIP(containers, "ghost"); err == nil {
		t.Fatalf("expected error for missing container")
	}
}
