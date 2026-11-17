package nginx

import (
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

const basicAuthTestHash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"

func withBasicAuth(d ProxyHostConfigData, passAuth bool, items ...model.AccessListItem) ProxyHostConfigData {
	d.AccessList = &model.AccessList{
		ID: "0b5e0c3a-8f2d-4c1e-9a7b-6d5e4f3a2b1c", Name: "family", SatisfyAny: true, PassAuth: passAuth, Items: items,
		AuthUsers: []model.AccessListAuthUser{{Username: "alice", PasswordHash: basicAuthTestHash}},
	}
	return d
}

// A list with accounts asks for them on every content location, leaves the
// ACME path open, and keeps the credentials from the backend unless the list
// passes them on (#387).
func TestBasicAuthRendersLoginAndKeepsACMEOpen(t *testing.T) {
	for _, tc := range []struct {
		name string
		data ProxyHostConfigData
	}{{"http", fixtureHTTPOnly()}, {"https", fixtureHTTPSForce()}} {
		conf := renderForTest(t, withBasicAuth(tc.data, false))
		for _, want := range []string{
			`auth_basic "Restricted";`,
			`auth_basic_user_file /etc/nginx/conf.d/includes/htpasswd/0b5e0c3a_8f2d_4c1e_9a7b_6d5e4f3a2b1c;`,
			"satisfy any;",
		} {
			if !strings.Contains(conf, want) {
				t.Errorf("%s: config lacks %q", tc.name, want)
			}
		}
		if acme := blockAt(conf, "location /.well-known/acme-challenge/"); !strings.Contains(acme, "auth_basic off;") {
			t.Errorf("%s: the ACME location asks for the password:\n%s", tc.name, acme)
		}
		// Only a list with addresses ends in deny all: without them it would
		// refuse every account under satisfy all.
		if strings.Contains(conf, "deny all;") {
			t.Errorf("%s: a list without addresses renders deny all", tc.name)
		}
		for _, b := range splitServerBlocks(t, conf) {
			loc := blockAt(b, "location / {")
			if loc != "" && !strings.Contains(loc, `proxy_set_header Authorization "";`) {
				t.Errorf("%s: location / passes the credentials on:\n%s", tc.name, loc)
			}
		}

		passed := renderForTest(t, withBasicAuth(tc.data, true))
		if strings.Contains(passed, `proxy_set_header Authorization "";`) {
			t.Errorf("%s: pass_auth on, yet the credentials are removed", tc.name)
		}
	}

	withAddr := renderForTest(t, withBasicAuth(fixtureHTTPOnly(), false,
		model.AccessListItem{Directive: "allow", Address: "192.0.2.0/24"}))
	if !strings.Contains(withAddr, "allow 192.0.2.0/24;") || !strings.Contains(withAddr, "deny all;") {
		t.Error("a list with addresses and accounts lost its rules")
	}
}

// The challenge gate answers with 401 too, so next to the accounts it turns
// into a plain block, as next to ForwardAuth; ForwardAuth itself wins over the
// accounts (the API refuses the pair).
func TestBasicAuthGivesWayToForwardAuthAndTakesOverTheGate(t *testing.T) {
	d := withBasicAuth(fixtureHTTPOnly(), false)
	d.GeoRestriction = geoChallenge(false)
	if d.ChallengeGate() {
		t.Error("geo challenge still renders the gate next to the accounts")
	}
	cloudChallenge(&d)
	if d.CloudChallenge() {
		t.Error("cloud challenge still challenges next to the accounts")
	}
	if !d.AccessPhaseAuth() {
		t.Error("a host with accounts does not count as asking for a login")
	}
	if g := geoWithOwnAuthRequest(d.Host, d.GeoRestriction, d.BasicAuth()); g.ChallengeMode {
		t.Error("geoWithOwnAuthRequest kept challenge mode next to the accounts")
	}

	fa := withBasicAuth(fixtureHTTPSForce(), false)
	fa.AuthProvider = &model.AuthProvider{ID: "00000000-0000-0000-0000-0000000000fa", Type: "authelia", ProviderURL: "https://auth.example.com"}
	if fa.BasicAuth() {
		t.Error("BasicAuth is on next to ForwardAuth")
	}
	if conf := renderForTest(t, fa); strings.Contains(conf, "auth_basic") {
		t.Error("ForwardAuth host renders auth_basic")
	}
}

// Only well-formed accounts reach the file, one line each.
func TestHtpasswdContentLeavesOutUnusableAccounts(t *testing.T) {
	list := &model.AccessList{ID: "l", AuthUsers: []model.AccessListAuthUser{
		{Username: "alice", PasswordHash: basicAuthTestHash},
		{Username: "bad name", PasswordHash: basicAuthTestHash},
		{Username: "eve:x", PasswordHash: basicAuthTestHash},
		{Username: "bob", PasswordHash: "plain"},
		{Username: "#hidden", PasswordHash: basicAuthTestHash},
		{Username: "carol", PasswordHash: basicAuthTestHash + "\nmallory:" + basicAuthTestHash},
	}}
	if got, want := string(htpasswdContent(list)), "alice:"+basicAuthTestHash+"\n"; got != want {
		t.Errorf("htpasswd file = %q, want %q", got, want)
	}
}
