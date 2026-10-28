package nginx

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A host with ForwardAuth blocks the visitors its geo restriction refuses
// instead of challenging them: the challenge gate would put a second
// auth_request into location /, and nginx -t refuses a block with two, so a
// global GeoIP default in challenge mode could not be saved (#341). A host
// without ForwardAuth keeps the challenge.
func TestGeoChallengeOnAForwardAuthHostBlocks(t *testing.T) {
	const id = "00000000-0000-0000-0000-0000000003a1"
	apID := "00000000-0000-0000-0000-0000000003a2"
	geo := &model.GeoRestriction{ProxyHostID: id, Mode: "whitelist", Countries: []string{"BY"}, Enabled: true, ChallengeMode: true, AllowPrivateIPs: true}

	host := goldenBaseHost(id, "fa-geo.example.com")
	host.AuthProviderID = &apID
	data := ProxyHostConfigData{Host: host, GlobalSettings: baseGlobalSettings(), GeoRestriction: geo,
		AuthProvider: &model.AuthProvider{ID: apID, Name: "authelia", Type: "authelia", ProviderURL: "http://127.0.0.1:9091", TimeoutMs: 5000, Enabled: true}}
	// Callers that read the data without rendering it (the DNS entry host
	// index) must see no gate either.
	if data.ChallengeGate() {
		t.Errorf("ChallengeGate = true on a ForwardAuth host")
	}
	withList := data
	withList.AccessList = &model.AccessList{ID: "00000000-0000-0000-0000-0000000003a3", Name: "office", SatisfyAny: true,
		Items: []model.AccessListItem{{ID: "i1", Directive: "allow", Address: "192.0.2.64/26"}}}
	if !withList.ListSkipsLogin() {
		t.Errorf("ListSkipsLogin = false, but with no gate the list renders satisfy any and skips the ForwardAuth login")
	}
	out := generateForTest(t, data)

	n := 0
	for _, line := range strings.Split(locationBlock(t, out, "    location / {"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "auth_request ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("location / has %d auth_request directives, want 1 (ForwardAuth's)", n)
	}
	if strings.Contains(out, "/_challenge/validate") {
		t.Errorf("the challenge gate is rendered on a ForwardAuth host")
	}
	if !strings.Contains(out, "Direct Block Mode") {
		t.Errorf("the geo restriction does not block on a ForwardAuth host")
	}
	if !geo.ChallengeMode {
		t.Errorf("rendering changed the caller's geo restriction")
	}

	plain := generateForTest(t, ProxyHostConfigData{Host: goldenBaseHost(id, "geo.example.com"), GlobalSettings: baseGlobalSettings(), GeoRestriction: geo})
	if !strings.Contains(plain, "auth_request /_challenge/validate;") || strings.Contains(plain, "Direct Block Mode") {
		t.Errorf("a host without ForwardAuth does not challenge")
	}
}
