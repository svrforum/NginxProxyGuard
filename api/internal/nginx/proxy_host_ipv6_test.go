package nginx

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestProxyHostForwardAddressFormatting(t *testing.T) {
	for _, address := range []struct {
		host string
		want string
	}{
		{"fd00::1", "[fd00::1]:8080"},
		{"::1", "[::1]:8080"},
		{"192.0.2.10", "192.0.2.10:8080"},
		{"backend.example.com", "backend.example.com:8080"},
	} {
		for _, fixture := range []struct {
			name string
			data func() ProxyHostConfigData
		}{
			{"http", fixtureHTTPOnly},
			{"https", fixtureHTTPSForce},
			{"waf", fixtureWAFBlocking},
			{"cache", fixtureCacheEnabled},
		} {
			t.Run(fixture.name+"/"+address.host, func(t *testing.T) {
				data := fixture.data()
				data.Host.ForwardHost = address.host
				var out bytes.Buffer
				if err := renderProxyHostConfig(context.Background(), &out, data); err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{
					"server " + address.want + ";",
					"proxy_redirect " + data.Host.ForwardScheme + "://" + address.want + "/ /;",
				} {
					if !strings.Contains(out.String(), want) {
						t.Errorf("generated config missing %q", want)
					}
				}
			})
		}
	}
}

func TestProxyHostIPv6LoadBalancedUpstream(t *testing.T) {
	data := fixtureUpstreamLB()
	data.Upstream.Servers[0].Address = "fd00::1"
	data.Upstream.Servers[0].Weight = 2
	var out bytes.Buffer
	if err := renderProxyHostConfig(context.Background(), &out, data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server [fd00::1]:8080 weight=2;",
		"server 10.0.0.2:8080;",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("generated config missing %q", want)
		}
	}
}
