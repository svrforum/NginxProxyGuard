package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// dnsTestHosts serves the hosts of each list and their config data.
type dnsTestHosts struct {
	byList map[string][]model.ProxyHost
	noList []model.ProxyHost // hosts without an access list
	data   map[string]nginx.ProxyHostConfigData
	fail   map[string]bool
}

func (h *dnsTestHosts) GetByAccessListID(ctx context.Context, accessListID string) ([]model.ProxyHost, error) {
	return append([]model.ProxyHost(nil), h.byList[accessListID]...), nil
}

// GetAllEnabled serves every enabled host, with a list or without, as the
// repository does.
func (h *dnsTestHosts) GetAllEnabled(ctx context.Context) ([]model.ProxyHost, error) {
	var out []model.ProxyHost
	for _, listID := range dnsSortedKeys(h.byList) {
		for _, host := range h.byList[listID] {
			if host.Enabled {
				out = append(out, host)
			}
		}
	}
	for _, host := range h.noList {
		if host.Enabled {
			out = append(out, host)
		}
	}
	return out, nil
}

func (h *dnsTestHosts) BuildConfigData(ctx context.Context, host *model.ProxyHost) (nginx.ProxyHostConfigData, error) {
	if h.fail[host.ID] {
		return nginx.ProxyHostConfigData{}, errors.New("geo lookup failed")
	}
	return h.data[host.ID], nil
}

// add registers a host using list with the given config data.
func (h *dnsTestHosts) add(host model.ProxyHost, list *model.AccessList, data nginx.ProxyHostConfigData) {
	listID := list.ID
	host.AccessListID = &listID
	cp := host
	data.Host, data.AccessList = &cp, list
	h.byList[list.ID] = append(h.byList[list.ID], host)
	h.data[host.ID] = data
}

const (
	dnsGateH1 = "00000000-0000-4000-8000-000000000001" // satisfy all
	dnsGateH2 = "00000000-0000-4000-8000-000000000002" // satisfy any + ForwardAuth
	dnsGateH3 = "00000000-0000-4000-8000-000000000003" // satisfy any + auth_basic inside a location
	dnsGateH4 = "00000000-0000-4000-8000-000000000004" // satisfy any + auth_basic inside a location + geo challenge
	dnsGateH5 = "00000000-0000-4000-8000-000000000005" // Advanced Config allow/deny of its own
	dnsGateH7 = "00000000-0000-4000-8000-000000000007" // stream host
	dnsGateH8 = "00000000-0000-4000-8000-000000000008" // config data cannot be built
	dnsGateH9 = "00000000-0000-4000-8000-000000000009" // disabled
)

// dnsGateRig: list A (satisfy all) and list B (satisfy any) both hold
// partner.example.com, published as 203.0.113.10; nginx may still allow
// 203.0.113.9, removed from list A's file a moment ago.
func dnsGateRig(t *testing.T) (*dnsTestRig, *dnsTestHosts) {
	t.Helper()
	r := newDNSTestRig(t)
	r.store.setRefs(dnsRef(dnsTestListA, "partner.example.com"), dnsRef(dnsTestListB, "partner.example.com"))
	r.store.put(dnsOKRow("partner.example.com", 1, "203.0.113.10"))
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.svc.pendingRevoke[dnsSegKey(dnsACL(dnsTestListA), "partner.example.com")] = dnsRevokeEntry{
		Scope: dnsACL(dnsTestListA), Name: "partner.example.com", Gen: 2, Addrs: []string{"203.0.113.9"}}

	items := []model.AccessListItem{
		{Directive: "allow", Address: "198.51.100.7"},
		{Directive: "deny", Address: "198.51.100.0/24"},
		{Directive: "deny", Address: "all", Hostname: "partner.example.com"},
	}
	listA := &model.AccessList{ID: dnsTestListA, Items: items}
	listB := &model.AccessList{ID: dnsTestListB, SatisfyAny: true, Items: items}
	forwardAuth := &model.AuthProvider{ID: "p1", Enabled: true}
	trusted := []string{"192.0.2.5"}
	host := func(id, domain string) model.ProxyHost {
		return model.ProxyHost{ID: id, DomainNames: []string{domain}, Enabled: true}
	}
	h := &dnsTestHosts{byList: map[string][]model.ProxyHost{}, data: map[string]nginx.ProxyHostConfigData{}, fail: map[string]bool{}}
	h.add(host(dnsGateH1, "app1.example.com"), listA, nginx.ProxyHostConfigData{GlobalTrustedIPs: trusted})
	h.add(host(dnsGateH2, "app2.example.com"), listB, nginx.ProxyHostConfigData{AuthProvider: forwardAuth})
	h3 := host(dnsGateH3, "app3.example.com")
	h3.AdvancedConfig = "location /admin { auth_basic \"admin\"; auth_basic_user_file /etc/nginx/htpasswd; }"
	h.add(h3, listB, nginx.ProxyHostConfigData{})
	// A login next to the challenge gate. Not ForwardAuth: on such a host the
	// geo challenge renders as a block, with no gate (#341).
	h4 := host(dnsGateH4, "app4.example.com")
	h4.AdvancedConfig = "location /admin { auth_basic \"admin\"; auth_basic_user_file /etc/nginx/htpasswd; }"
	h.add(h4, listB, nginx.ProxyHostConfigData{GeoRestriction: &model.GeoRestriction{Enabled: true, ChallengeMode: true}})
	h5 := host(dnsGateH5, "app5.example.com")
	h5.AdvancedConfig = "location /status { allow all; }"
	h.add(h5, listA, nginx.ProxyHostConfigData{})
	h7 := host(dnsGateH7, "app7.example.com")
	h7.ProxyType = model.ProxyTypeStream
	h.add(h7, listA, nginx.ProxyHostConfigData{})
	h.add(host(dnsGateH8, "app8.example.com"), listA, nginx.ProxyHostConfigData{})
	h.fail[dnsGateH8] = true
	h9 := host(dnsGateH9, "app9.example.com")
	h9.Enabled = false
	h.add(h9, listA, nginx.ProxyHostConfigData{})
	r.svc.hosts, r.svc.builder = h, h
	r.svc.rebuildHostIndex(context.Background(), r.mustRefs(), "")
	return r, h
}

// The fail2ban gate table: which host 403s are left out of fail2ban.
func TestDNSExemptAccessDenial(t *testing.T) {
	r, _ := dnsGateRig(t)
	cases := []struct {
		host, client string
		exempt       bool
		why          string
	}{
		{dnsGateH1, "203.0.113.99", true, "outside the list: the list's own 403"},
		{dnsGateH1, "::ffff:203.0.113.99", true, "an IPv4-mapped client is the IPv4 client"},
		{dnsGateH1, "198.51.100.8", true, "the list's explicit deny"},
		{dnsGateH1, "192.0.2.5", false, "a global trusted IP is allowed"},
		{dnsGateH1, "198.51.100.7", false, "an IP row allows it"},
		{dnsGateH1, "203.0.113.10", false, "a domain address allows it"},
		{dnsGateH1, "203.0.113.9", false, "a revocation nginx may not have taken yet"},
		{dnsGateH1, "not-an-address", false, "unreadable client"},
		{dnsGateH2, "203.0.113.99", false, "satisfy any + ForwardAuth: the login decides"},
		{dnsGateH3, "203.0.113.99", false, "satisfy any + auth_basic in a location"},
		{dnsGateH4, "203.0.113.99", true, "next to the challenge gate satisfy any is not rendered"},
		{dnsGateH5, "203.0.113.99", false, "Advanced Config with allow/deny of its own"},
		{dnsGateH7, "203.0.113.99", false, "stream host"},
		{dnsGateH8, "203.0.113.99", false, "config data could not be built"},
		{dnsGateH9, "203.0.113.99", false, "disabled host"},
		{"00000000-0000-4000-8000-0000000000ff", "203.0.113.99", false, "a host without a domain list"},
	}
	for _, c := range cases {
		if got := r.svc.ExemptAccessDenial(context.Background(), c.host, c.client, r.clock.Now()); got != c.exempt {
			t.Errorf("%s (%s %s): exempt = %v, want %v", c.why, c.host[len(c.host)-2:], c.client, got, c.exempt)
		}
	}
}

// The collector reads a log line seconds after the request, so the gate
// judges each line as nginx had the domain files when the request came in.
// The partner's address changes: nginx drops the old one at once (taken at
// S) and takes the new one after two answers and the gap (taken at T). A
// 403 the new address got before T, or while old workers still served the
// previous files, was the list's own; one it gets later is not. A 403 the
// old address got before S was not the list's; one it gets after S is.
func TestDNSExemptAccessDenialJudgesTheRequestTime(t *testing.T) {
	r, _ := dnsGateRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	r.lookup.set("partner.example.com", "203.0.113.11")
	check := func(client string, at time.Time, want bool, why string) {
		t.Helper()
		if got := r.svc.ExemptAccessDenial(ctx, dnsGateH1, client, at); got != want {
			t.Errorf("%s (%s at %s): exempt = %v, want %v", why, client, at.Format("15:04:05"), got, want)
		}
	}

	r.tick(t) // the old address is revoked at once
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("after the first answer the file = %v, want the old address out", got)
	}
	revokedAt := r.clock.Now()
	check("203.0.113.10", revokedAt.Add(-3*time.Second), false, "nginx still allowed the old address: its 403 was not the list's")
	check("203.0.113.10", revokedAt.Add(10*time.Second), true, "nginx no longer allows the old address: its 403 is the list's")

	r.clock.Advance(time.Minute)
	r.tick(t)
	r.clock.Advance(5 * time.Minute)
	r.tick(t) // the new address is published after two answers and the gap
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.11"}) {
		t.Fatalf("after the gap the file = %v, want the new address", got)
	}
	publishedAt := r.clock.Now()
	check("203.0.113.11", publishedAt.Add(-3*time.Second), true, "a 403 from before the publish was the list's")
	check("203.0.113.11", publishedAt.Add(2*time.Second), true, "old workers may still serve the files without it")
	check("203.0.113.11", publishedAt.Add(30*time.Second), false, "nginx allows the new address: its 403 is not the list's")
	check("203.0.113.99", publishedAt.Add(30*time.Second), true, "a client the list denies stays exempt")
	check("203.0.113.10", revokedAt.Add(-3*time.Second), false, "the old address's stretch is still remembered")
}

// The access log stamps a request with its second. When nginx drops an
// address partway through a second, a line stamped with that second may have
// come in after the drop, when the list denied it: it is judged as after the
// drop and left out, so a client whose address is revoked while it still
// sends requests collects no count in that second. A line stamped with the
// second before counts: nginx allowed the address then.
func TestDNSExemptAccessDenialJudgesTheRevocationSecondAsAfter(t *testing.T) {
	r, _ := dnsGateRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	r.lookup.set("partner.example.com", "203.0.113.11")
	r.clock.Advance(244 * time.Millisecond)
	r.tick(t) // nginx drops 203.0.113.10 at 12:00:00.244
	if got := r.partnerFile(t); len(got) != 0 {
		t.Fatalf("after the first answer the file = %v, want the old address out", got)
	}
	second := r.clock.Now().Truncate(time.Second)
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.10", second.Add(-time.Second)) {
		t.Error("a line stamped the second before the drop: nginx allowed the address then, so its 403 must count")
	}
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.10", second) {
		t.Error("a line stamped the second of the drop may have come after it: the list's own 403 must be left out")
	}
}

// The record of what nginx allowed holds what the gate can still be asked:
// an address nginx stopped allowing more than 10 minutes ago is forgotten,
// and one that keeps coming and going keeps its latest stretches. An older
// reload's hook that runs after a newer one's never moves the record back.
func TestDNSAllowedRecordIsBoundedAndNeverMovesBack(t *testing.T) {
	r := newDNSTestRig(t)
	scope := dnsACL(dnsTestListA)
	key := dnsSegKey(scope, "partner.example.com")
	gen := int64(0)
	write := func(addrs ...string) {
		gen++
		r.svc.disk[key] = dnsDiskEntry{Scope: scope, Name: "partner.example.com", Gen: gen, Addrs: addrs}
	}
	take := func(addrs ...string) {
		write(addrs...)
		r.svc.afterReload(r.svc.beforeReload(), nginx.ReloadAccepted, nil)
		r.settle()
	}
	spans := func(addr string) []dnsAllowSpan {
		r.svc.diskMu.Lock()
		defer r.svc.diskMu.Unlock()
		return append([]dnsAllowSpan(nil), r.svc.allowed[scope][addr]...)
	}

	for i := 0; i < 10; i++ {
		take("203.0.113.10")
		r.clock.Advance(time.Second)
		take()
		r.clock.Advance(time.Second)
	}
	got := spans("203.0.113.10")
	if len(got) != dnsAllowSpansMax {
		t.Fatalf("after 10 stretches the record holds %d, want the newest %d", len(got), dnsAllowSpansMax)
	}
	if last, want := got[len(got)-1].until, r.clock.Now().Add(-time.Second); !last.Equal(want) {
		t.Fatalf("the newest stretch ends at %v, want %v: the newest are kept", last, want)
	}

	r.clock.Advance(dnsAllowMemory)
	take("203.0.113.11")
	if got := spans("203.0.113.10"); len(got) != 0 {
		t.Fatalf("10 minutes after nginx stopped allowing it the record still holds %d stretches", len(got))
	}

	older := r.svc.beforeReload() // holds 203.0.113.11
	write("203.0.113.12")
	newer := r.svc.beforeReload()
	r.svc.afterReload(newer, nginx.ReloadAccepted, nil)
	r.svc.afterReload(older, nginx.ReloadAccepted, nil)
	r.settle()
	later := r.clock.Now().Add(time.Minute)
	if !r.svc.dnsAllowedAt(scope, "203.0.113.12", later) || r.svc.dnsAllowedAt(scope, "203.0.113.11", later) {
		t.Fatal("the older reload's hook ran last and moved the record back to 203.0.113.11")
	}
}

func TestDNSLoginBypassHosts(t *testing.T) {
	r, h := dnsGateRig(t)
	got := r.svc.LoginBypassHosts(dnsTestListB)
	if len(got) != 2 || got[0].ID != dnsGateH2 || got[0].Domain != "app2.example.com" || got[1].ID != dnsGateH3 {
		t.Fatalf("list B = %+v, want app2 (ForwardAuth) and app3 (auth_basic); app4's challenge gate keeps the login", got)
	}
	if got := r.svc.LoginBypassHosts(dnsTestListA); len(got) != 0 {
		t.Fatalf("list A (satisfy all) = %+v, want none", got)
	}

	// Rebuilding one list keeps the others.
	h.byList[dnsTestListB] = nil
	r.svc.rebuildHostIndex(context.Background(), r.mustRefs(), dnsTestListB)
	if got := r.svc.LoginBypassHosts(dnsTestListB); len(got) != 0 {
		t.Fatalf("list B after its rebuild = %+v, want none", got)
	}
	if !r.svc.ExemptAccessDenial(context.Background(), dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("list A's hosts must survive a rebuild of list B")
	}
}

// Building the host index costs about a dozen queries per host, so a
// check rebuilds it only when there is none or it is 5 minutes old. A mark
// (a list save, a settings change, a reload nginx took) rebuilds it at once,
// in the background, and the check after that does not build it again.
func TestDNSHostIndexIsRebuiltEveryFiveMinutesOrWhenMarked(t *testing.T) {
	r, _ := dnsGateRig(t)
	r.svc.lastGC = r.clock.Now()
	r.lookup.set("partner.example.com", "203.0.113.10")
	r.svc.hostIdx.Store(nil)

	r.tick(t)
	first := r.svc.hostIdx.Load()
	r.clock.Advance(4 * time.Minute)
	r.tick(t)
	if first == nil || r.svc.hostIdx.Load() != first {
		t.Fatal("two checks within 5 minutes must build the host index once")
	}

	r.clock.Advance(time.Minute)
	r.tick(t)
	aged := r.svc.hostIdx.Load()
	if aged == first {
		t.Fatal("a check 5 minutes after the last build must rebuild the host index")
	}

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // e.g. a host save's reload
	r.settle()
	taken := r.svc.hostIdx.Load()
	if taken == aged {
		t.Fatal("a reload nginx took must rebuild the host index at once")
	}
	r.clock.Advance(time.Minute)
	r.tick(t)
	if r.svc.hostIdx.Load() != taken {
		t.Fatal("the check after that rebuild must not build the host index again")
	}

	r.svc.SettingsChanged(context.Background(), model.DefaultDNSEntrySettings(), model.DefaultDNSEntrySettings())
	r.settle()
	if r.svc.hostIdx.Load() == taken {
		t.Fatal("a settings change must rebuild the host index at once")
	}
}

// dnsBlockingHosts holds every read of list A's hosts until it is opened, so
// a test can look at the fail2ban gate while a rebuild of the host index
// runs. Each build reads list A once: reads counts the builds, most the
// builds that ever ran at once.
type dnsBlockingHosts struct {
	*dnsTestHosts
	started chan struct{} // one value each time a read of list A begins
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	reads   int
	running int
	most    int
}

func newDNSBlockingHosts(t *testing.T, h *dnsTestHosts) *dnsBlockingHosts {
	b := &dnsBlockingHosts{dnsTestHosts: h, started: make(chan struct{}, 16), release: make(chan struct{})}
	t.Cleanup(b.open) // runs before the rig waits for its goroutines
	return b
}

func (b *dnsBlockingHosts) GetByAccessListID(ctx context.Context, accessListID string) ([]model.ProxyHost, error) {
	if accessListID == dnsTestListA {
		b.mu.Lock()
		b.reads++
		b.running++
		b.most = max(b.most, b.running)
		b.mu.Unlock()
		b.started <- struct{}{}
		<-b.release
		b.mu.Lock()
		b.running--
		b.mu.Unlock()
	}
	return b.dnsTestHosts.GetByAccessListID(ctx, accessListID)
}

// open lets every read go on.
func (b *dnsBlockingHosts) open() { b.once.Do(func() { close(b.release) }) }

// waitBuild waits until a rebuild reads list A's hosts.
func (b *dnsBlockingHosts) waitBuild(t *testing.T) {
	t.Helper()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("no rebuild of the host index started")
	}
}

func (b *dnsBlockingHosts) counts() (reads, most int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reads, b.most
}

// After a reload the index may no longer say what a host renders. Until a
// rebuild that began after the reload is in place, the gate leaves nothing
// out: every 403 is counted.
func TestDNSMarkedHostIndexExemptsNothingUntilItIsRebuilt(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("before the reload, the list's own 403 must be left out")
	}
	hosts := newDNSBlockingHosts(t, h)
	r.svc.hosts = hosts

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // a host save's reload
	hosts.waitBuild(t)
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("while the host index is rebuilt after a reload, a 403 must be counted")
	}
	hosts.open()
	r.settle()
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("once the rebuild is in place, the list's own 403 must be left out again")
	}
}

// dnsGateWatchNginx asks the fail2ban gate right after each apply's reload is
// taken, before the check goes on: a reload that marks the host index leaves
// the gate counting at that moment.
type dnsGateWatchNginx struct {
	*dnsTestNginx
	ask  func() bool
	seen []bool
}

func (n *dnsGateWatchNginx) ApplyDNSIncludes(ctx context.Context) nginx.DNSApplyResult {
	res := n.dnsTestNginx.ApplyDNSIncludes(ctx)
	n.seen = append(n.seen, n.ask())
	return res
}

// The DNS applier's own reload is for the include files: nothing a host
// renders changes, so it leaves the host index in place, and the gate leaves
// the list's own 403s out through a revocation and a publish with no moment
// where it counts them. A reload from any other path, here a host save's,
// still marks the index, and the gate counts until the rebuild is in place.
func TestDNSApplierReloadLeavesTheHostIndexInPlace(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	r.svc.lastGC = r.clock.Now()
	r.lookup.set("partner.example.com", "203.0.113.11")
	hosts := newDNSBlockingHosts(t, h) // a rebuild waits until the gate was asked
	r.svc.hosts = hosts
	watch := &dnsGateWatchNginx{dnsTestNginx: r.nginx, ask: func() bool {
		defer hosts.open()
		return r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now())
	}}
	r.svc.nginx = watch
	marks := r.svc.hostIdxMarks.Load()

	r.tick(t) // revokes 203.0.113.10
	r.clock.Advance(time.Minute)
	r.tick(t)
	r.clock.Advance(5 * time.Minute)
	r.tick(t) // publishes 203.0.113.11
	if got := r.partnerFile(t); !dnsEqual(got, []string{"203.0.113.11"}) {
		t.Fatalf("after the gap the file = %v, want the new address", got)
	}
	if len(watch.seen) != 2 {
		t.Fatalf("%d applies, want the revocation's and the publish's", len(watch.seen))
	}
	for i, exempt := range watch.seen {
		if !exempt {
			t.Errorf("apply %d: right after the applier's reload the gate counted the list's own 403", i+1)
		}
	}
	if got := r.svc.hostIdxMarks.Load() - marks; got != 0 {
		t.Errorf("the applier's reloads marked the host index %d time(s), want none", got)
	}

	saving := newDNSBlockingHosts(t, h)
	r.svc.hosts = saving
	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // a host save's reload
	saving.waitBuild(t)
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("while the host index is rebuilt after a host save's reload, a 403 must be counted")
	}
	saving.open()
	r.settle()
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("once the rebuild is in place, the list's own 403 must be left out again")
	}
}

// A host save's reload whose acceptance was not seen is taken with the next
// reload nginx takes. When that is the applier's own, the host save's reload
// still marks the host index; the applier's alone does not.
func TestDNSApplierReloadMarksForAHostSaveItTakesAlong(t *testing.T) {
	r := newDNSTestRig(t)
	hooks := r.svc.ReloadHooks()
	marks := r.svc.hostIdxMarks.Load()
	hooks.After(hooks.BeforeDNSApply(), nginx.ReloadAccepted, nil)
	r.settle()
	if got := r.svc.hostIdxMarks.Load() - marks; got != 0 {
		t.Fatalf("the applier's reload alone marked the host index %d time(s), want none", got)
	}
	hooks.After(hooks.Before(), nginx.ReloadUnconfirmed, &nginx.ReloadSnapshot{}) // a host save's, not seen taken
	r.settle()
	hooks.After(hooks.BeforeDNSApply(), nginx.ReloadAccepted, nil)
	r.settle()
	if got := r.svc.hostIdxMarks.Load() - marks; got != 1 {
		t.Fatalf("the host index was marked %d time(s), want once: the host save's reload was taken with the applier's", got)
	}
}

// A burst of reloads (SyncAll, a run of saves) marks the index again and
// again. Marks made while a rebuild runs start no rebuild of their own:
// exactly one more rebuild, after the running one, covers them all.
func TestDNSMarksDuringARebuildShareOneMoreRebuild(t *testing.T) {
	r, h := dnsGateRig(t)
	hosts := newDNSBlockingHosts(t, h)
	r.svc.hosts = hosts

	r.svc.markHostIndexDirty()
	hosts.waitBuild(t)
	for i := 0; i < 5; i++ {
		r.svc.markHostIndexDirty()
	}
	hosts.open()
	r.settle()

	if reads, most := hosts.counts(); reads != 2 || most != 1 {
		t.Fatalf("%d rebuilds, at most %d at once; want the running one and exactly one more for the five marks, never two at once", reads, most)
	}
	if !r.svc.ExemptAccessDenial(context.Background(), dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("after the rebuilds the index must be current again")
	}
}

// A host save that changes what the host renders reloads nginx, and the
// reload rebuilds the host index at once, without waiting for a check: a
// host that dropped its domain list stops being exempt, the others stay.
func TestDNSAReloadRebuildsTheHostIndexAtOnce(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	h.drop(dnsTestListA, dnsGateH1) // app1 no longer uses list A

	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil) // app1's save reloads nginx
	r.settle()

	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Error("app1 dropped its domain list: its 403s must be counted")
	}
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH4, "203.0.113.99", r.clock.Now()) {
		t.Error("app4 still uses its list: once the index is rebuilt, its list's own 403 must be left out")
	}
}

// drop takes a host off a list, as a host save that changes its list does.
func (h *dnsTestHosts) drop(listID, hostID string) {
	var kept []model.ProxyHost
	for _, host := range h.byList[listID] {
		if host.ID != hostID {
			kept = append(kept, host)
		}
	}
	h.byList[listID] = kept
}

// dnsPanickingBuilder panics on the first config data it is asked for, as a
// bug in a host's render data would, then builds as dnsTestHosts does.
type dnsPanickingBuilder struct {
	*dnsTestHosts
	panicked atomic.Bool
}

func (b *dnsPanickingBuilder) BuildConfigData(ctx context.Context, host *model.ProxyHost) (nginx.ProxyHostConfigData, error) {
	if b.panicked.CompareAndSwap(false, true) {
		panic("broken render data")
	}
	return b.dnsTestHosts.BuildConfigData(ctx, host)
}

// Every reload rebuilds the host index in the background, so a panic there
// (a bug in a host's render data) must not end the process. The index stays
// stale and every 403 counts, until the next mark rebuilds it.
func TestDNSHostIndexRebuildSurvivesAPanic(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	logs := captureLog(t)
	r.svc.builder = &dnsPanickingBuilder{dnsTestHosts: h}

	r.svc.markHostIndexDirty()
	r.settle()
	if n := strings.Count(logs.String(), "[DNSEntries] ERROR: "); n != 1 {
		t.Fatalf("log = %q, want one [DNSEntries] ERROR line for the rebuild that panicked", logs.String())
	}
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("after a rebuild that panicked the index is stale: the 403 must be counted")
	}

	r.svc.markHostIndexDirty()
	r.settle()
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("the next mark must rebuild the index, and the list's own 403 be left out again")
	}
}

// dnsFailingHosts cannot read the hosts of the lists in failLists.
type dnsFailingHosts struct {
	*dnsTestHosts
	mu        sync.Mutex
	failLists map[string]bool
}

func (f *dnsFailingHosts) GetByAccessListID(ctx context.Context, accessListID string) ([]model.ProxyHost, error) {
	f.mu.Lock()
	failing := f.failLists[accessListID]
	f.mu.Unlock()
	if failing {
		return nil, errors.New("connection refused")
	}
	return f.dnsTestHosts.GetByAccessListID(ctx, accessListID)
}

func (f *dnsFailingHosts) setFailing(listID string, failing bool) {
	f.mu.Lock()
	f.failLists[listID] = failing
	f.mu.Unlock()
}

// When a list's hosts cannot be read, a rebuild keeps the list's last
// answer, so the index it puts in place is as stale as the one before: the
// gate counts the 403 until a build reads the list again. The next check
// makes that build.
func TestDNSHostIndexKeptFromAFailedReadStaysStaleUntilTheCheckRebuildsIt(t *testing.T) {
	r, h := dnsGateRig(t)
	ctx := context.Background()
	captureLog(t) // the failed read's WARN line
	r.svc.lastGC = r.clock.Now()
	r.lookup.set("partner.example.com", "203.0.113.10")
	hosts := &dnsFailingHosts{dnsTestHosts: h, failLists: map[string]bool{dnsTestListA: true}}
	r.svc.hosts = hosts

	// app1 drops list A and its save reloads nginx, but list A's hosts
	// cannot be read: its last answer, with app1, is kept.
	h.drop(dnsTestListA, dnsGateH1)
	hooks := r.svc.ReloadHooks()
	hooks.After(hooks.Before(), nginx.ReloadAccepted, nil)
	r.settle()
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Fatal("the rebuild kept list A's last answer: the index must stay stale and the 403 be counted")
	}

	hosts.setFailing(dnsTestListA, false)
	r.tick(t)
	if n := r.nginx.applyCount(); n != 0 {
		t.Fatalf("%d applies: no reload may rebuild the index here, the check must", n)
	}
	if r.svc.ExemptAccessDenial(ctx, dnsGateH1, "203.0.113.99", r.clock.Now()) {
		t.Error("app1 dropped its domain list: once the check rebuilt the index, its 403s must be counted")
	}
	if !r.svc.ExemptAccessDenial(ctx, dnsGateH4, "203.0.113.99", r.clock.Now()) {
		t.Error("app4 still uses its list: once the check rebuilt the index, its list's own 403 must be left out")
	}
}

const (
	dnsTestListC = "33333333-3333-4333-8333-333333333333" // satisfy all, no domain rows
	dnsTestListD = "44444444-4444-4444-8444-444444444444" // satisfy any, no domain rows
	dnsTestListE = "55555555-5555-4555-8555-555555555555" // no entries

	dnsTrustH1 = "00000000-0000-4000-8000-000000000021" // list C: the trusted domains are in its block
	dnsTrustH2 = "00000000-0000-4000-8000-000000000022" // list D + ForwardAuth: the login decides
	dnsTrustH3 = "00000000-0000-4000-8000-000000000023" // list D + auth_basic inside a location + geo challenge
	dnsTrustH4 = "00000000-0000-4000-8000-000000000024" // list C + Advanced Config allow/deny of its own
	dnsTrustH5 = "00000000-0000-4000-8000-000000000025" // list E: no access list block
	dnsTrustH6 = "00000000-0000-4000-8000-000000000026" // no access list
)

// dnsTrustedGateRig: the global trusted list holds office.example.com,
// published as 192.0.2.20 and 192.0.2.140; nginx may still allow
// 192.0.2.19, removed a moment ago. No access list has a domain row. The
// static trusted IP is 192.0.2.5; lists C and D allow 192.0.2.7 and deny
// 192.0.2.128/25 before the trusted domains.
func dnsTrustedGateRig(t *testing.T) (*dnsTestRig, *dnsTestHosts) {
	t.Helper()
	r := newDNSTestRig(t)
	const name = "office.example.com"
	r.store.setRefs(model.DNSReference{Scope: model.DNSScopeKindTrusted, Name: name})
	r.store.put(dnsOKRow(name, 1, "192.0.2.20", "192.0.2.140"))
	if err := r.svc.ReconcileFiles(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	r.svc.pendingRevoke[dnsSegKey(model.DNSScopeKindTrusted, name)] = dnsRevokeEntry{
		Scope: model.DNSScopeKindTrusted, Name: name, Gen: 2, Addrs: []string{"192.0.2.19"}}

	items := []model.AccessListItem{
		{Directive: "allow", Address: "192.0.2.7"},
		{Directive: "deny", Address: "192.0.2.128/25"},
	}
	listC := &model.AccessList{ID: dnsTestListC, Items: items}
	listD := &model.AccessList{ID: dnsTestListD, SatisfyAny: true, Items: items}
	listE := &model.AccessList{ID: dnsTestListE}
	forwardAuth := &model.AuthProvider{ID: "p1", Enabled: true}
	trusted := func(d nginx.ProxyHostConfigData) nginx.ProxyHostConfigData {
		d.GlobalTrustedIPs, d.TrustedHostnames = []string{"192.0.2.5"}, []string{name}
		return d
	}
	host := func(id, domain string) model.ProxyHost {
		return model.ProxyHost{ID: id, DomainNames: []string{domain}, Enabled: true}
	}
	h := &dnsTestHosts{byList: map[string][]model.ProxyHost{}, data: map[string]nginx.ProxyHostConfigData{}, fail: map[string]bool{}}
	h.add(host(dnsTrustH1, "trust1.example.com"), listC, trusted(nginx.ProxyHostConfigData{}))
	h.add(host(dnsTrustH2, "trust2.example.com"), listD, trusted(nginx.ProxyHostConfigData{AuthProvider: forwardAuth}))
	t3 := host(dnsTrustH3, "trust3.example.com")
	t3.AdvancedConfig = "location /admin { auth_basic \"admin\"; auth_basic_user_file /etc/nginx/htpasswd; }"
	h.add(t3, listD, trusted(nginx.ProxyHostConfigData{GeoRestriction: &model.GeoRestriction{Enabled: true, ChallengeMode: true}}))
	h4 := host(dnsTrustH4, "trust4.example.com")
	h4.AdvancedConfig = "location /status { allow all; }"
	h.add(h4, listC, trusted(nginx.ProxyHostConfigData{}))
	h.add(host(dnsTrustH5, "trust5.example.com"), listE, trusted(nginx.ProxyHostConfigData{}))
	h6 := host(dnsTrustH6, "trust6.example.com")
	h.noList = append(h.noList, h6)
	h.data[dnsTrustH6] = trusted(nginx.ProxyHostConfigData{Host: &h6})
	r.svc.hosts, r.svc.builder = h, h
	r.svc.rebuildHostIndex(context.Background(), r.mustRefs(), "")
	return r, h
}

// On a host whose access list has no domain row but includes the global
// trusted domains, nginx walks the static trusted IPs, the list's rules
// (first match), then the trusted domains' file, and denies the rest. The
// gate walks the same: the list's 403 for a client outside both is left out;
// one for an address a trusted domain had, or may still have in nginx,
// counts; an address the list denies stays denied, a trusted domain's
// included.
func TestExemptAccessDenialWalksTrustedDomainsAfterListRules(t *testing.T) {
	r, _ := dnsTrustedGateRig(t)
	ctx := context.Background()
	cases := []struct {
		client string
		exempt bool
		why    string
	}{
		{"192.0.2.99", true, "outside the list and every trusted entry: the list's own 403"},
		{"::ffff:192.0.2.99", true, "an IPv4-mapped client is the IPv4 client"},
		{"192.0.2.20", false, "a trusted domain's address: nginx allowed it, so its 403 was not the list's"},
		{"192.0.2.19", false, "a trusted domain's address nginx may not have dropped yet"},
		{"192.0.2.140", true, "the list's deny comes first: a trusted domain's address stays denied"},
		{"192.0.2.200", true, "the list's deny"},
		{"192.0.2.7", false, "the list allows it"},
		{"192.0.2.5", false, "a static global trusted IP"},
	}
	for _, c := range cases {
		if got := r.svc.ExemptAccessDenial(ctx, dnsTrustH1, c.client, r.clock.Now()); got != c.exempt {
			t.Errorf("%s (%s): exempt = %v, want %v", c.why, c.client, got, c.exempt)
		}
	}
}

// With a trusted domain the host index holds every enabled HTTP host with an
// access list, and the gate covers the ones whose list block includes the
// trusted domains. A satisfy-any list on a host with a login lets its
// addresses skip the login, so the trusted domains are left out of its
// block and the login decides its 403s: that host is left out, as is a host
// whose Advanced Config has access rules, a list without entries and a host
// without a list. Without a trusted domain, a list without domain rows is
// not indexed at all.
func TestHostIndexLeavesOutHostsWhereTrustedDomainsAreNotInjected(t *testing.T) {
	r, _ := dnsTrustedGateRig(t)
	ctx := context.Background()
	cases := []struct {
		host   string
		exempt bool
		why    string
	}{
		{dnsTrustH1, true, "satisfy all: the trusted domains are in the list block"},
		{dnsTrustH2, false, "satisfy any + ForwardAuth: the login decides, no trusted domain is in the block"},
		{dnsTrustH3, true, "next to the challenge gate satisfy any is not rendered: the trusted domains are in the block"},
		{dnsTrustH4, false, "Advanced Config with allow/deny of its own"},
		{dnsTrustH5, false, "a list without entries renders no block"},
		{dnsTrustH6, false, "no access list"},
	}
	for _, c := range cases {
		if got := r.svc.ExemptAccessDenial(ctx, c.host, "192.0.2.99", r.clock.Now()); got != c.exempt {
			t.Errorf("%s (%s): exempt = %v, want %v", c.why, c.host[len(c.host)-2:], got, c.exempt)
		}
	}

	r.store.setRefs() // the trusted domain is removed
	r.svc.rebuildHostIndex(ctx, r.mustRefs(), "")
	if r.svc.ExemptAccessDenial(ctx, dnsTrustH1, "192.0.2.99", r.clock.Now()) {
		t.Error("without a trusted domain a list without domain rows is not indexed: its 403s count")
	}
}

// dnsFailingAllHosts cannot read the enabled hosts while failing is set.
type dnsFailingAllHosts struct {
	*dnsTestHosts
	failing atomic.Bool
}

func (f *dnsFailingAllHosts) GetAllEnabled(ctx context.Context) ([]model.ProxyHost, error) {
	if f.failing.Load() {
		return nil, errors.New("connection refused")
	}
	return f.dnsTestHosts.GetAllEnabled(ctx)
}

// While the trusted list has a domain, a whole build reads every host in one
// query. When that read fails the build keeps the last answer, so the index
// stays stale and the gate counts every 403 until a build reads the hosts
// again.
func TestHostIndexOfEveryListHostStaysStaleWhenTheHostsCannotBeRead(t *testing.T) {
	r, h := dnsTrustedGateRig(t)
	ctx := context.Background()
	logs := captureLog(t)
	hosts := &dnsFailingAllHosts{dnsTestHosts: h}
	hosts.failing.Store(true)
	r.svc.hosts = hosts

	r.svc.markHostIndexDirty() // e.g. a trusted list save
	r.settle()
	if r.svc.ExemptAccessDenial(ctx, dnsTrustH1, "192.0.2.99", r.clock.Now()) {
		t.Fatal("the rebuild kept the last answer: the index must stay stale and the 403 be counted")
	}
	if n := strings.Count(logs.String(), "[DNSEntries] WARN: could not read the hosts with an access list"); n != 1 {
		t.Fatalf("log = %q, want one WARN line for the failed read", logs.String())
	}

	hosts.failing.Store(false)
	r.svc.markHostIndexDirty()
	r.settle()
	if !r.svc.ExemptAccessDenial(ctx, dnsTrustH1, "192.0.2.99", r.clock.Now()) {
		t.Fatal("once the hosts are read again, the list's own 403 must be left out again")
	}
}
