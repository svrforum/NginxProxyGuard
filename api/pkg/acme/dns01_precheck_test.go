package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"nginx-proxy-guard/internal/model"
)

const (
	challengeFQDN  = "_acme-challenge.example.com."
	challengeValue = "dns01-expected-value"
)

// fakeTXTLookup stands in for the container's resolver.
type fakeTXTLookup struct {
	records []string
	err     error

	names       []string      // the names looked up
	hasDeadline bool          // whether the last look-up had a deadline
	left        time.Duration // how long the last look-up had
}

func (f *fakeTXTLookup) lookup(ctx context.Context, name string) ([]string, error) {
	f.names = append(f.names, name)
	var deadline time.Time
	deadline, f.hasDeadline = ctx.Deadline()
	f.left = time.Until(deadline)
	return f.records, f.err
}

// fakeLegoCheck stands in for lego's own check, which asks every
// authoritative nameserver of the zone for the record.
type fakeLegoCheck struct {
	ok  bool
	err error

	calls int
}

func (f *fakeLegoCheck) check(fqdn, value string) (bool, error) {
	f.calls++
	if fqdn != challengeFQDN || value != challengeValue {
		return false, fmt.Errorf("lego's check got %s %s", fqdn, value)
	}
	return f.ok, f.err
}

// legoTimedOut is what lego's own check returns when a nameserver does not
// answer: it names the nameserver and both ends of the query.
var legoTimedOut = fmt.Errorf("authoritative nameservers: %w", &dns01.DNSError{
	Message: "DNS call error", NS: "ns5.example.net.:53",
	Err: errors.New("read udp 192.0.2.10:40000->198.51.100.53:53: i/o timeout"),
})

// installedPreCheck returns the check that opts make lego run before it asks
// the CA to validate, or nil when lego runs only its own. lego keeps it in an
// unexported field, which is read here the one way Go allows; if a lego
// upgrade moves it, this fails rather than passes.
func installedPreCheck(t *testing.T, opts []dns01.ChallengeOption) dns01.WrapPreCheckFunc {
	t.Helper()
	chlg := dns01.NewChallenge(nil, nil, nil, opts...)
	preCheck := reflect.ValueOf(chlg).Elem().FieldByName("preCheck")
	if !preCheck.IsValid() || preCheck.Kind() != reflect.Struct {
		t.Fatal("lego's dns01.Challenge has no preCheck field any more: update installedPreCheck")
	}
	field := preCheck.FieldByName("checkFunc")
	if !field.IsValid() || field.Type() != reflect.TypeFor[dns01.WrapPreCheckFunc]() {
		t.Fatal("lego's pre-check has no checkFunc field any more: update installedPreCheck")
	}
	if field.IsNil() {
		return nil
	}
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(dns01.WrapPreCheckFunc)
}

// Dynu's challenge runs NPG's check, built on the look-up it is given: lego's
// own check first, then the resolver. Every other provider keeps lego's own
// check and its other defaults.
func TestDNS01ChallengeOptionsWrapLegosCheckOnlyForDynu(t *testing.T) {
	resolver := &fakeTXTLookup{records: []string{challengeValue}}
	opts := dns01ChallengeOptionsWith(model.DNSProviderDynu, resolver.lookup)
	if len(opts) != 1 {
		t.Fatalf("Dynu gets %d challenge options, want the one that wraps lego's check", len(opts))
	}
	check := installedPreCheck(t, opts)
	if check == nil {
		t.Fatal("Dynu's challenge runs lego's own check only")
	}
	lego := &fakeLegoCheck{err: legoTimedOut}
	if ok, err := check("example.com", challengeFQDN, challengeValue, lego.check); !ok || err != nil {
		t.Errorf("the installed check = %v, %v; want true, nil from the resolver", ok, err)
	}
	if lego.calls != 1 || len(resolver.names) != 1 {
		t.Errorf("lego's check ran %d time(s) and the resolver was asked %d time(s); want once each", lego.calls, len(resolver.names))
	}
	if installedPreCheck(t, dns01ChallengeOptions(model.DNSProviderDynu)) == nil {
		t.Error("dns01ChallengeOptions does not wrap lego's check for Dynu")
	}

	for _, providerType := range []string{model.DNSProviderCloudflare, model.DNSProviderRoute53, model.DNSProviderDuckDNS, model.DNSProviderIonos} {
		if got := len(dns01ChallengeOptionsWith(providerType, resolver.lookup)); got != 0 {
			t.Errorf("%s gets %d challenge options, want none: lego's defaults", providerType, got)
		}
		if got := len(dns01ChallengeOptions(providerType)); got != 0 {
			t.Errorf("%s gets %d challenge options from dns01ChallengeOptions, want none", providerType, got)
		}
	}
}

// Where every Dynu nameserver answers, lego's own check confirms the record
// within seconds, as it always has, and the resolver is not asked: it may
// still remember that the name did not exist.
func TestDynuDNS01CheckPassesOnLegosCheckWithoutTheResolver(t *testing.T) {
	lego := &fakeLegoCheck{ok: true}
	resolver := &fakeTXTLookup{err: &net.DNSError{Err: "no such host", Name: challengeFQDN, IsNotFound: true}}
	check := dns01PreCheckFor(model.DNSProviderDynu, resolver.lookup)

	ok, err := check("example.com", challengeFQDN, challengeValue, lego.check)
	if !ok || err != nil {
		t.Fatalf("check = %v, %v; want true, nil", ok, err)
	}
	if lego.calls != 1 {
		t.Errorf("lego's check ran %d time(s), want once", lego.calls)
	}
	if len(resolver.names) != 0 {
		t.Errorf("the resolver was asked for %q after lego's check confirmed the record", resolver.names)
	}
}

// Where lego's check does not confirm the record — a nameserver does not
// answer, or it simply says no — an ordinary look-up through the resolver,
// which skips the nameservers that do not answer, can. It passes once the
// expected value is among the TXT records, and each look-up has a deadline of
// its own.
func TestDynuDNS01CheckFallsBackToTheResolver(t *testing.T) {
	cases := []struct {
		name string
		lego *fakeLegoCheck
	}{
		{"lego's check fails", &fakeLegoCheck{err: legoTimedOut}},
		{"lego's check says no", &fakeLegoCheck{ok: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fakeTXTLookup{records: []string{"an older challenge", challengeValue, "v=spf1 -all"}}
			check := dns01PreCheckFor(model.DNSProviderDynu, resolver.lookup)

			ok, err := check("example.com", challengeFQDN, challengeValue, tc.lego.check)
			if !ok || err != nil {
				t.Fatalf("check = %v, %v; want true, nil", ok, err)
			}
			if tc.lego.calls != 1 {
				t.Errorf("lego's check ran %d time(s), want once, before the resolver", tc.lego.calls)
			}
			if len(resolver.names) != 1 || resolver.names[0] != challengeFQDN {
				t.Errorf("looked up %q, want %q once", resolver.names, challengeFQDN)
			}
			if !resolver.hasDeadline || resolver.left <= 0 || resolver.left > 10*time.Second {
				t.Errorf("the look-up had a deadline: %v, %s left; want a deadline of at most 10s", resolver.hasDeadline, resolver.left)
			}
		})
	}
}

// When neither confirms the record, the check fails with the reason in a few
// words, so lego keeps polling and quotes the last reason when time runs out.
// That text is stored with the certificate and sent in notifications, so it
// quotes neither lego's error nor the resolver's: they name nameserver and
// resolver addresses.
func TestDynuDNS01CheckKeepsPollingWithAGenericReason(t *testing.T) {
	const resolverAddr = "192.0.2.53:53"
	cases := []struct {
		name     string
		lego     *fakeLegoCheck
		records  []string
		err      error
		reason   string
		resolver string // the resolver's own wording, which must not be quoted
	}{
		{"no such record", &fakeLegoCheck{err: legoTimedOut}, nil,
			&net.DNSError{Err: "no such host", Name: challengeFQDN, Server: resolverAddr, IsNotFound: true}, "no such record", "no such host"},
		{"a different value", &fakeLegoCheck{err: legoTimedOut}, []string{"an older challenge"}, nil,
			"found a different value", "an older challenge"},
		{"resolver timed out", &fakeLegoCheck{err: legoTimedOut}, nil,
			&net.DNSError{Err: "i/o timeout", Name: challengeFQDN, Server: resolverAddr, IsTimeout: true}, "lookup timed out", "i/o timeout"},
		{"deadline passed", &fakeLegoCheck{err: legoTimedOut}, nil,
			fmt.Errorf("lookup %s on %s: %w", challengeFQDN, resolverAddr, context.DeadlineExceeded), "lookup timed out", "deadline exceeded"},
		{"server failure", &fakeLegoCheck{err: legoTimedOut}, nil,
			&net.DNSError{Err: "server misbehaving", Name: challengeFQDN, Server: resolverAddr, IsTemporary: true}, "lookup failed", "server misbehaving"},
		{"lego's check says no", &fakeLegoCheck{ok: false}, nil,
			&net.DNSError{Err: "no such host", Name: challengeFQDN, Server: resolverAddr, IsNotFound: true}, "no such record", "no such host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			check := dns01PreCheckFor(model.DNSProviderDynu, (&fakeTXTLookup{records: tc.records, err: tc.err}).lookup)

			ok, err := check("example.com", challengeFQDN, challengeValue, tc.lego.check)
			if ok || err == nil {
				t.Fatalf("check = %v, %v; want false and a reason, so lego keeps polling", ok, err)
			}
			want := "TXT record for " + challengeFQDN + " not visible yet: authoritative nameservers: not confirmed; resolver: " + tc.reason
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
			for _, quoted := range []string{"ns5.example.net", "198.51.100.53", "192.0.2.10", "192.0.2.53", "DNS call error", tc.resolver} {
				if strings.Contains(err.Error(), quoted) {
					t.Errorf("the error quotes %q: %v", quoted, err)
				}
			}
			if tc.lego.calls != 1 {
				t.Errorf("lego's check ran %d time(s), want once", tc.lego.calls)
			}
		})
	}
}

// Dynu's records may need the resolver, which may still remember that the
// name did not exist, so lego gives them ten minutes, looking every ten
// seconds. Building the provider makes no request.
func TestDynuDNS01WaitsTenMinutesLookingEveryTenSeconds(t *testing.T) {
	p, err := (&Service{}).newDNS01Provider(dnsProviderOf(t, model.DNSProviderDynu, model.DynuCredentials{APIKey: "dynu-key-0123456789"}))
	if err != nil {
		t.Fatal(err)
	}
	timeouts, ok := p.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("the Dynu provider has no Timeout")
	}
	if timeout, interval := timeouts.Timeout(); timeout != 10*time.Minute || interval != 10*time.Second {
		t.Errorf("Timeout() = %s, %s; want 10m0s, 10s", timeout, interval)
	}
}
