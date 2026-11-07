package service

import (
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// The exception domains of the merged URI block (#320): the global names
// when the global block is on, with the scope uri:global, and the host's
// when the host's block is on, with the host's scope. A name on both lists
// is rendered once, with the host's scope.
func TestMergeURIBlocksMergesDomainsHostScopeWins(t *testing.T) {
	rule := model.URIBlockRule{ID: "r1", Pattern: "/admin", MatchType: model.URIMatchPrefix, Enabled: true}
	hostRef := func(name string) model.DNSRef { return model.DNSRef{Scope: "uri:" + dnsTestHostID, Name: name} }
	globalRef := func(name string) model.DNSRef { return model.DNSRef{Scope: "uri:global", Name: name} }
	for _, tc := range []struct {
		name             string
		globalOn, hostOn bool
		want             []model.DNSRef
	}{
		{"both off", false, false, nil},
		{"global on", true, false, []model.DNSRef{globalRef("office.example.com"), globalRef("partner.example.com")}},
		{"host on", false, true, []model.DNSRef{hostRef("partner.example.com"), hostRef("shop.example.com")}},
		{"both on", true, true, []model.DNSRef{hostRef("partner.example.com"), hostRef("shop.example.com"), globalRef("office.example.com")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			global := &model.GlobalURIBlock{Enabled: tc.globalOn, Rules: []model.URIBlockRule{rule},
				ExceptionHostnames: []string{"office.example.com", "partner.example.com"}}
			host := &model.URIBlock{ProxyHostID: dnsTestHostID, Enabled: tc.hostOn, Rules: []model.URIBlockRule{rule},
				ExceptionHostnames: []string{"partner.example.com", "shop.example.com"}}
			got := mergeURIBlocks(global, host)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %+v, want no URI block", got)
				}
				return
			}
			if got == nil || !reflect.DeepEqual(got.ExceptionDNS, tc.want) {
				t.Fatalf("ExceptionDNS = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A host rule for a path the global block also blocks is one location, so its
// own exception IPs (#343) join the global rule's there, and the global
// block's rule keeps its list.
func TestMergeURIBlocksJoinsTheExceptionsOfOnePath(t *testing.T) {
	global := &model.GlobalURIBlock{Enabled: true, Rules: []model.URIBlockRule{
		{ID: "g1", Pattern: "/admin", MatchType: model.URIMatchPrefix, Enabled: true, ExceptionIPs: []string{"203.0.113.5"}},
	}}
	host := &model.URIBlock{ProxyHostID: dnsTestHostID, Enabled: true, Rules: []model.URIBlockRule{
		{ID: "h1", Pattern: "/admin", MatchType: model.URIMatchPrefix, Enabled: true, ExceptionIPs: []string{"198.51.100.7", "203.0.113.5"}},
		{ID: "h2", Pattern: "/user/login", MatchType: model.URIMatchPrefix, Enabled: true, ExceptionIPs: []string{"192.0.2.9"}},
	}}
	got := mergeURIBlocks(global, host)
	if got == nil || len(got.Rules) != 2 {
		t.Fatalf("merged rules = %+v, want /admin and /user/login", got)
	}
	if want := []string{"203.0.113.5", "198.51.100.7"}; !reflect.DeepEqual(got.Rules[0].ExceptionIPs, want) {
		t.Errorf("/admin exceptions = %q, want %q", got.Rules[0].ExceptionIPs, want)
	}
	if want := []string{"192.0.2.9"}; !reflect.DeepEqual(got.Rules[1].ExceptionIPs, want) {
		t.Errorf("/user/login exceptions = %q, want %q", got.Rules[1].ExceptionIPs, want)
	}
	if want := []string{"203.0.113.5"}; !reflect.DeepEqual(global.Rules[0].ExceptionIPs, want) {
		t.Errorf("the global rule's own list became %q, want %q", global.Rules[0].ExceptionIPs, want)
	}
}
