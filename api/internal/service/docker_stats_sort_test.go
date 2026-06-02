package service

import "testing"

func TestSortContainerInfo(t *testing.T) {
	info := &DockerContainerInfo{
		Networks: []DockerContainerNetwork{{Name: "zeta"}, {Name: "alpha"}, {Name: "mid"}},
		Ports: []DockerContainerPort{
			{ContainerPort: 8080, Protocol: "tcp"},
			{ContainerPort: 22, Protocol: "tcp"},
			{ContainerPort: 8080, Protocol: "udp"},
			{ContainerPort: 443, Protocol: "tcp"},
		},
	}
	sortContainerInfo(info)
	wantNets := []string{"alpha", "mid", "zeta"}
	for i, n := range wantNets {
		if info.Networks[i].Name != n {
			t.Fatalf("network[%d]=%q want %q", i, info.Networks[i].Name, n)
		}
	}
	wantPorts := []int{22, 443, 8080, 8080}
	for i, p := range wantPorts {
		if info.Ports[i].ContainerPort != p {
			t.Fatalf("port[%d]=%d want %d", i, info.Ports[i].ContainerPort, p)
		}
	}
	if info.Ports[2].Protocol != "tcp" || info.Ports[3].Protocol != "udp" {
		t.Fatalf("equal-port protocol order wrong: %q,%q", info.Ports[2].Protocol, info.Ports[3].Protocol)
	}
}

func TestSortContainers(t *testing.T) {
	cs := []DockerContainerInfo{{Name: "redis"}, {Name: "api"}, {Name: "nginx"}}
	sortContainers(cs)
	want := []string{"api", "nginx", "redis"}
	for i, n := range want {
		if cs[i].Name != n {
			t.Fatalf("container[%d]=%q want %q", i, cs[i].Name, n)
		}
	}
}
