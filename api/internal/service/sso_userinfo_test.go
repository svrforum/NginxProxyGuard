package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"nginx-proxy-guard/internal/model"
)

// fakeIdP serves just enough discovery and UserInfo for the merge path.
//
// It models Authelia's default claims policy: the ID token carries the subject
// and nothing else, and everything the flow needs is only at UserInfo. (#238)
func fakeIdP(t *testing.T, userinfo map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/keys",
			"userinfo_endpoint":      srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userinfo)
	})
	t.Cleanup(srv.Close)
	return srv
}

// The bug ydrob hit: Authelia keeps email out of the ID token, so the flow saw
// no email at all — account linking could not match and JIT refused the sign-in
// for a missing address.
func TestClaimsMissingFromTheIDTokenComeFromUserInfo(t *testing.T) {
	srv := fakeIdP(t, map[string]any{
		"sub":            "user-1",
		"email":          "ada@example.com",
		"email_verified": true,
		"name":           "Ada",
		"groups":         []string{"admins"},
	})
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	s := &SSOService{}
	// What the ID token gave us: a subject and nothing else.
	claims := &model.SSOClaims{Subject: "user-1"}
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", false)

	if claims.Email != "ada@example.com" {
		t.Errorf("email not taken from UserInfo: %q", claims.Email)
	}
	if !claims.EmailVerified {
		t.Error("email_verified not taken from UserInfo — linking would still refuse")
	}
	if claims.Name != "Ada" {
		t.Errorf("name = %q", claims.Name)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "admins" {
		t.Errorf("groups = %v", claims.Groups)
	}
}

// The ID token is signed; UserInfo is not part of it. Where both speak, the
// token wins — otherwise a compromised UserInfo response could relabel a
// verified address.
func TestTheIDTokenWinsOverUserInfo(t *testing.T) {
	srv := fakeIdP(t, map[string]any{
		"sub":            "user-1",
		"email":          "attacker@example.com",
		"email_verified": true,
	})
	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.URL)

	s := &SSOService{}
	claims := &model.SSOClaims{Subject: "user-1", Email: "real@example.com", EmailVerified: true}
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", false)

	if claims.Email != "real@example.com" {
		t.Errorf("UserInfo overrode the signed token: %q", claims.Email)
	}
}

// Required by the spec: a response about a different subject is not about this
// user. Applying it would hand one account another's identity.
func TestUserInfoForAnotherSubjectIsIgnored(t *testing.T) {
	srv := fakeIdP(t, map[string]any{
		"sub":            "someone-else",
		"email":          "victim@example.com",
		"email_verified": true,
	})
	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.URL)

	s := &SSOService{}
	claims := &model.SSOClaims{Subject: "user-1"}
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", false)

	if claims.Email != "" {
		t.Errorf("claims from a different subject were applied: %q", claims.Email)
	}
}

// Providers that answer nothing useful must leave the sign-in exactly as it was
// before this existed — Google and Dex already worked from the ID token alone.
func TestAFailingUserInfoLookupChangesNothing(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/keys",
			"userinfo_endpoint":      srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	})

	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.URL)
	s := &SSOService{}
	claims := &model.SSOClaims{Subject: "user-1", Email: "from-token@example.com", EmailVerified: true}
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", false)

	if claims.Email != "from-token@example.com" || !claims.EmailVerified {
		t.Errorf("a failed lookup damaged the token's own claims: %+v", claims)
	}
}

func TestDiscoverPreservesTrailingSlashInIssuer(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	//trailing slash가 있는 issuer
	issuer := srv.URL + "/application/o/test/"

	mux.HandleFunc("/application/o/test/.well-known/openid-configuration",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": srv.URL + "/auth",
				"token_endpoint":         srv.URL + "/token",
				"jwks_uri":               srv.URL + "/keys",
			})
		},
	)

	s := NewSSOService(nil, nil, nil, nil, nil)

	provider, err := s.discover(context.Background(), issuer)
	if err != nil {
		t.Fatalf("discovery failed for issuer with trailing slash: %v", err)
	}
	if provider == nil {
		t.Fatal("discovery returned nil provider")
	}
}

// An issuer without a trailing slash must keep working — that is every other
// provider, and the fix must not trade one shape for the other.
func TestDiscoverStillWorksWithoutTrailingSlash(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys",
		})
	})
	s := NewSSOService(nil, nil, nil, nil, nil)
	if _, err := s.discover(context.Background(), srv.URL); err != nil {
		t.Fatalf("plain issuer broke: %v", err)
	}
}

// Which shape is correct is the provider's choice, not ours: Authentik's
// document carries the trailing slash, Dex's does not. Whichever way the
// operator typed it into the form, discovery has to land — otherwise the fix
// for one provider is a new outage for the other.
func TestDiscoverAcceptsEitherTrailingSlashShape(t *testing.T) {
	for _, tc := range []struct {
		name           string
		path           string // what the provider's document calls itself
		configuredWith string
	}{
		{"document has the slash, operator omitted it", "/app/o/npg/", "/app/o/npg"},
		{"document omits the slash, operator added it", "/app/o/npg", "/app/o/npg/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			srv := httptest.NewServer(mux)
			defer srv.Close()

			issuer := srv.URL + tc.path
			mux.HandleFunc(strings.TrimRight(tc.path, "/")+"/.well-known/openid-configuration",
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer": issuer, "authorization_endpoint": srv.URL + "/auth",
						"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys",
					})
				})

			s := NewSSOService(nil, nil, nil, nil, nil)
			if _, err := s.discover(context.Background(), srv.URL+tc.configuredWith); err != nil {
				t.Fatalf("discovery refused %q when the document says %q: %v",
					tc.configuredWith, tc.path, err)
			}
		})
	}
}

// idpSplit serves an ID token's worth of claims and a UserInfo response
// separately, so the two can disagree about email_verified.
func idpSplit(t *testing.T, userinfo map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/keys",
			"userinfo_endpoint": srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userinfo)
	})
	t.Cleanup(srv.Close)
	return srv
}

// email_verified is optional in OIDC. A provider may put the address in the ID
// token and the verification flag only at UserInfo, and treating "unstated" as
// "false" refused those sign-ins with nothing to distinguish them from a
// genuinely unverified address. (#248)
func TestVerifiedFlagIsTakenFromUserInfoWhenTheTokenDidNotSayIt(t *testing.T) {
	srv := idpSplit(t, map[string]any{
		"sub": "user-1", "email": "ada@example.com", "email_verified": true,
	})
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	s := &SSOService{}
	// What the ID token gave us: subject and address, no verification flag.
	claims := &model.SSOClaims{Subject: "user-1", Email: "ada@example.com"}
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", false)

	if !claims.EmailVerified {
		t.Error("the provider asserted the address is verified at UserInfo; linking still refused it")
	}
	if claims.Email != "ada@example.com" {
		t.Errorf("email changed: %q", claims.Email)
	}
}

// The ID token is signed. Where it states the flag, UserInfo must not override
// it — otherwise an unverified address could be laundered into a verified one.
func TestAnExplicitFalseInTheTokenIsNotOverridden(t *testing.T) {
	srv := idpSplit(t, map[string]any{
		"sub": "user-1", "email": "ada@example.com", "email_verified": true,
	})
	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.URL)

	s := &SSOService{}
	claims := &model.SSOClaims{Subject: "user-1", Email: "ada@example.com", EmailVerified: false}
	// true = the token stated it, and it stated false.
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", true)

	if claims.EmailVerified {
		t.Error("UserInfo overrode an explicit email_verified=false in the signed token")
	}
}

// A UserInfo response must not be able to mark a DIFFERENT address as verified
// than the one the signed token carried.
func TestUserInfoCannotVerifyADifferentAddress(t *testing.T) {
	srv := idpSplit(t, map[string]any{
		"sub": "user-1", "email": "attacker@example.com", "email_verified": true,
	})
	ctx := context.Background()
	provider, _ := oidc.NewProvider(ctx, srv.URL)

	s := &SSOService{}
	claims := &model.SSOClaims{Subject: "user-1", Email: "victim@example.com"}
	s.mergeUserInfoClaims(ctx, provider, &oauth2.Token{AccessToken: "t"}, claims, "groups", false)

	if claims.EmailVerified {
		t.Error("a UserInfo response about another address marked this one verified")
	}
	if claims.Email != "victim@example.com" {
		t.Errorf("email was replaced: %q", claims.Email)
	}
}
