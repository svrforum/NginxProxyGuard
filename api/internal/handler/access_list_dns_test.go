package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/dnsentry"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
)

const testListID = "00000000-0000-4000-8000-0000000016a1"

// listWriter may read and change access lists, and nothing else.
var listWriter = permGrants{"access:read": true, "access:write": true}

// callLog records what the fakes below were asked, in order.
type callLog struct{ calls []string }

func (l *callLog) add(format string, args ...interface{}) {
	l.calls = append(l.calls, fmt.Sprintf(format, args...))
}

// ctxNote marks a call made on a context that is already cancelled: a
// handler that did its work after the commit on the request's context lost
// it when the client left.
func ctxNote(ctx context.Context) string {
	if ctx.Err() != nil {
		return " (cancelled)"
	}
	return ""
}

// fakeAccessListStore keeps one list. committed, when set, runs once an
// update or a delete is stored: a test cancels the request there.
type fakeAccessListStore struct {
	log       *callLog
	list      *model.AccessList
	committed func()
}

func (s *fakeAccessListStore) List(context.Context, int, int) ([]model.AccessList, int, error) {
	if s.list == nil {
		return nil, 0, nil
	}
	return []model.AccessList{*s.list}, 1, nil
}

func (s *fakeAccessListStore) GetByID(_ context.Context, id string) (*model.AccessList, error) {
	s.log.add("get")
	if s.list == nil || s.list.ID != id {
		return nil, nil
	}
	list := *s.list
	return &list, nil
}

func (s *fakeAccessListStore) Create(_ context.Context, req *model.CreateAccessListRequest) (*model.AccessList, error) {
	s.log.add("create")
	stored := model.AccessList{ID: testListID, Name: req.Name, SatisfyAny: req.SatisfyAny == nil || *req.SatisfyAny, Items: storedItems(req.Items)}
	s.list = &stored
	list := stored
	return &list, nil
}

func (s *fakeAccessListStore) Update(_ context.Context, _ string, req *model.UpdateAccessListRequest) (*model.AccessList, error) {
	s.log.add("update")
	stored := *s.list
	if req.Name != nil {
		stored.Name = *req.Name
	}
	if req.SatisfyAny != nil {
		stored.SatisfyAny = *req.SatisfyAny
	}
	if req.Items != nil {
		stored.Items = storedItems(req.Items)
	}
	s.list = &stored
	list := stored
	if s.committed != nil {
		s.committed()
	}
	return &list, nil
}

func (s *fakeAccessListStore) Delete(context.Context, string) error {
	s.log.add("delete")
	if s.committed != nil {
		s.committed()
	}
	return nil
}

// storedItems is what the repository stores for checked request rules.
func storedItems(items []model.CreateAccessListItemRequest) []model.AccessListItem {
	out := make([]model.AccessListItem, 0, len(items))
	for _, it := range items {
		out = append(out, model.AccessListItem{AccessListID: testListID, Directive: it.Directive, Address: it.Address,
			Hostname: it.Hostname, Description: it.Description, SortOrder: it.SortOrder})
	}
	return out
}

// fakeAccessListHosts stands for the hosts that render a list. bounded
// records whether each regeneration had a deadline.
type fakeAccessListHosts struct {
	log     *callLog
	hostIDs []string
	bounded []bool
}

func (f *fakeAccessListHosts) RegenerateConfigsForAccessList(ctx context.Context, _ string) error {
	f.log.add("regen%s", ctxNote(ctx))
	_, ok := ctx.Deadline()
	f.bounded = append(f.bounded, ok)
	return nil
}

func (f *fakeAccessListHosts) GetHostIDsByAccessList(context.Context, string) ([]string, error) {
	f.log.add("hosts")
	return f.hostIDs, nil
}

func (f *fakeAccessListHosts) RegenerateConfigsForHostIDs(ctx context.Context, _ []string) error {
	f.log.add("regen hosts%s", ctxNote(ctx))
	_, ok := ctx.Deadline()
	f.bounded = append(f.bounded, ok)
	return nil
}

// fakeAccessListAudit records the audit calls.
type fakeAccessListAudit struct {
	log     *callLog
	updated map[string]interface{}
}

func (f *fakeAccessListAudit) LogAccessListCreated(context.Context, string) error {
	f.log.add("audit created")
	return nil
}

func (f *fakeAccessListAudit) LogAccessListUpdated(ctx context.Context, _ string, details map[string]interface{}) error {
	f.log.add("audit updated%s", ctxNote(ctx))
	f.updated = details
	return nil
}

func (f *fakeAccessListAudit) LogAccessListDeleted(ctx context.Context, _ string) error {
	f.log.add("audit deleted%s", ctxNote(ctx))
	return nil
}

func (f *fakeAccessListAudit) LogDNSEntryConfirmed(ctx context.Context, name string, addrs []string, canonical string, scopes []string) error {
	f.log.add("audit confirmed %s %v %s %v%s", name, addrs, canonical, scopes, ctxNote(ctx))
	return nil
}

// fakeAccessListDNS stands for the DNS entry service.
type fakeAccessListDNS struct {
	log        *callLog
	limitScope string
	limitErr   error
	syncErr    error
	statuses   map[string]model.DNSEntryStatus
	view       model.DNSStatusView
	bypass     []model.DNSHostRef
	refs       []model.DNSReference
	confirmed  model.DNSEntryStatus
	result     nginx.DNSApplyResult
	confirmErr error
	// confirming, when set, runs while Confirm applies: a test cancels the
	// request there, after the confirm is stored.
	confirming func()
}

func (f *fakeAccessListDNS) ValidateScopeNames(_ context.Context, scope string, names []string) error {
	f.log.add("limits %v", names)
	f.limitScope = scope
	return f.limitErr
}

func (f *fakeAccessListDNS) SyncScope(ctx context.Context, scope string, names []string) error {
	f.log.add("sync %s %v%s", scope, names, ctxNote(ctx))
	return f.syncErr
}

func (f *fakeAccessListDNS) Statuses(_ context.Context, _ []string, view model.DNSStatusView) (map[string]model.DNSEntryStatus, error) {
	f.view = view
	return f.statuses, nil
}

func (f *fakeAccessListDNS) LoginBypassHosts(string) []model.DNSHostRef { return f.bypass }

func (f *fakeAccessListDNS) References(context.Context, string) ([]model.DNSReference, error) {
	return f.refs, nil
}

func (f *fakeAccessListDNS) Confirm(_ context.Context, name string, expected []string, expectedCanonical string) (model.DNSEntryStatus, nginx.DNSApplyResult, error) {
	f.log.add("confirm %s %v %s", name, expected, expectedCanonical)
	if f.confirming != nil {
		f.confirming()
	}
	return f.confirmed, f.result, f.confirmErr
}

// newDNSListHandler returns a handler over the fakes; list is the stored one.
func newDNSListHandler(list *model.AccessList) (*AccessListHandler, *callLog, *fakeAccessListDNS, *fakeAccessListAudit) {
	calls := &callLog{}
	dns := &fakeAccessListDNS{log: calls}
	audit := &fakeAccessListAudit{log: calls}
	h := &AccessListHandler{
		repo:       &fakeAccessListStore{log: calls, list: list},
		proxyHosts: &fakeAccessListHosts{log: calls},
		audit:      audit,
		dns:        dns,
	}
	return h, calls, dns, audit
}

// domainRule is a domain rule as the repository stores it.
func domainRule(name string, sortOrder int) model.AccessListItem {
	return model.AccessListItem{AccessListID: testListID, Directive: "deny", Address: "all", Hostname: name, SortOrder: sortOrder}
}

// addressRule is any other rule as the repository stores it.
func addressRule(directive, address string, sortOrder int) model.AccessListItem {
	return model.AccessListItem{AccessListID: testListID, Directive: directive, Address: address, SortOrder: sortOrder}
}

// A refused rule answers {error, field, code}, all strings, with the rule's
// request position in field, before anything is saved.
func TestAccessListRuleErrorsNameTheFieldAndCode(t *testing.T) {
	cases := []struct{ name, items, field, code string }{
		{"domain without kind", `[{"directive":"allow","address":"192.0.2.1"},{"directive":"allow","address":"partner.example.com"}]`,
			"items[1].address", "hostname_needs_kind"},
		{"denied domain", `[{"directive":"deny","address":"partner.example.com","kind":"hostname"}]`,
			"items[0].directive", "deny_hostname"},
		{"same domain twice", `[{"directive":"allow","address":"partner.example.com","kind":"hostname"},{"directive":"allow","address":"Partner.Example.com.","kind":"hostname"}]`,
			"items[1].address", "duplicate_hostname"},
		{"deny all next to a domain", `[{"directive":"deny","address":"all"},{"directive":"allow","address":"partner.example.com","kind":"hostname"}]`,
			"items[0].address", "deny_all_with_hostname"},
		{"deny all after a domain names the deny all rule", `[{"directive":"allow","address":"partner.example.com","kind":"hostname"},{"directive":"allow","address":"192.0.2.1"},{"directive":"deny","address":"all"}]`,
			"items[2].address", "deny_all_with_hostname"},
		{"legacy rule the list does not hold", `[{"directive":"allow","address":"old.example.com","kind":"legacy"}]`,
			"items[0].address", "legacy_not_in_list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, calls, _, _ := newDNSListHandler(nil)
			rec := callWithGrants(t, h.Create, listWriter, http.MethodPost, `{"name":"partners","items":`+tc.items+`}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %s: %v", rec.Body, err)
			}
			if body["field"] != tc.field || body["code"] != tc.code || !strings.HasPrefix(body["error"], tc.field) {
				t.Errorf("body = %v, want field %s and code %s", body, tc.field, tc.code)
			}
			if len(calls.calls) != 0 {
				t.Errorf("a refused list went on to %v", calls.calls)
			}
		})
	}
}

// More domains than the settings allow is a 400 with code limit, before
// anything is saved. A new list is checked under a scope no list owns.
func TestAccessListOverTheDomainLimitIsRefusedBeforeSaving(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(nil)
	dns.limitErr = &service.DNSLimitError{Field: "items", Limit: 1, Got: 2}
	rec := callWithGrants(t, h.Create, listWriter, http.MethodPost,
		`{"name":"partners","items":[{"directive":"allow","address":"a.example.com","kind":"hostname"},{"directive":"allow","address":"b.example.com","kind":"hostname"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "limit" || body["field"] != "items" || body["error"] != dns.limitErr.Error() {
		t.Errorf("body = %v", body)
	}
	if kind, _, ok := model.ParseDNSScope(dns.limitScope); !ok || kind != model.DNSScopeKindAccessList {
		t.Errorf("a new list was checked as scope %q, want an access list scope", dns.limitScope)
	}
	if want := []string{"limits [a.example.com b.example.com]"}; !reflect.DeepEqual(calls.calls, want) {
		t.Errorf("calls = %v, want %v (nothing saved)", calls.calls, want)
	}
}

// A save hands the list's domains to the DNS service after the list is
// stored and before the hosts are regenerated, so a domain taken out leaves
// its file empty even if the regeneration fails. The audit
// names domain rules by their domain.
func TestAccessListUpdateHandsTheDomainsOverBeforeRegenerating(t *testing.T) {
	h, calls, dns, audit := newDNSListHandler(&model.AccessList{ID: testListID, Name: "partners", Items: []model.AccessListItem{
		addressRule("allow", "192.0.2.10", 0), domainRule("old.example.com", 1),
	}})
	rec := callWithGrants(t, h.Update, listWriter, http.MethodPut,
		`{"items":[{"directive":"allow","address":"192.0.2.10"},{"directive":"allow","address":"new.example.com","kind":"hostname"}]}`,
		"id", testListID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	want := []string{
		"get",
		"limits [new.example.com]",
		"update",
		"audit updated",
		"sync acl:" + testListID + " [new.example.com]",
		"regen",
	}
	if !reflect.DeepEqual(calls.calls, want) {
		t.Errorf("calls = %v, want %v", calls.calls, want)
	}
	if dns.limitScope != "acl:"+testListID {
		t.Errorf("limits checked for scope %q", dns.limitScope)
	}
	wantAudit := map[string]interface{}{
		"added":   []string{"allow new.example.com (domain)"},
		"removed": []string{"allow old.example.com (domain)"},
	}
	if !reflect.DeepEqual(audit.updated, wantAudit) {
		t.Errorf("audit = %#v, want %#v", audit.updated, wantAudit)
	}
}

// The list is saved when handing the domains over fails: the hosts
// are still regenerated and the next DNS check does the hand-over.
func TestAccessListSaveGoesOnWhenTheDomainsCannotBeHandedOver(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(&model.AccessList{ID: testListID, Name: "partners"})
	dns.syncErr = errors.New("no space left on device")
	rec := callWithGrants(t, h.Update, listWriter, http.MethodPut,
		`{"items":[{"directive":"allow","address":"partner.example.com","kind":"hostname"}]}`, "id", testListID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	if last := calls.calls[len(calls.calls)-1]; last != "regen" {
		t.Errorf("calls = %v, want the regeneration last", calls.calls)
	}
}

// Deleting a list empties its domain files before the hosts that used it are
// regenerated.
func TestAccessListDeleteEmptiesItsDomainFiles(t *testing.T) {
	h, calls, _, _ := newDNSListHandler(&model.AccessList{ID: testListID, Name: "partners", Items: []model.AccessListItem{domainRule("partner.example.com", 0)}})
	h.proxyHosts.(*fakeAccessListHosts).hostIDs = []string{"00000000-0000-4000-8000-0000000016b1"}
	rec := callWithGrants(t, h.Delete, listWriter, http.MethodDelete, "", "id", testListID)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	want := []string{"get", "hosts", "delete", "audit deleted", "sync acl:" + testListID + " []", "regen hosts"}
	if !reflect.DeepEqual(calls.calls, want) {
		t.Errorf("calls = %v, want %v", calls.calls, want)
	}
}

// A client that leaves once the list is stored (a phone that closes during
// the domain lookups) cuts nothing short: the audit, the domain files and
// the hosts' regeneration still run, the regeneration with a deadline of its
// own. Otherwise nginx would keep the old rules, a removed IP still allowed,
// and nothing would retry.
func TestAccessListSaveFinishesWhenTheClientLeaves(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		h, calls, _, _ := newDNSListHandler(&model.AccessList{ID: testListID, Name: "partners", Items: []model.AccessListItem{
			addressRule("allow", "192.0.2.10", 0), domainRule("partner.example.com", 1),
		}})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h.repo.(*fakeAccessListStore).committed = cancel
		rec := callWithGrantsCtx(t, ctx, h.Update, listWriter, http.MethodPut,
			`{"items":[{"directive":"allow","address":"192.0.2.11"}]}`, "id", testListID)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d; body %s", rec.Code, rec.Body)
		}
		want := []string{"get", "update", "audit updated", "sync acl:" + testListID + " []", "regen"}
		if !reflect.DeepEqual(calls.calls, want) {
			t.Errorf("calls = %v, want %v", calls.calls, want)
		}
		if bounded := h.proxyHosts.(*fakeAccessListHosts).bounded; !reflect.DeepEqual(bounded, []bool{true}) {
			t.Errorf("regeneration deadlines = %v, want one", bounded)
		}
	})
	t.Run("delete", func(t *testing.T) {
		h, calls, _, _ := newDNSListHandler(&model.AccessList{ID: testListID, Name: "partners", Items: []model.AccessListItem{domainRule("partner.example.com", 0)}})
		hosts := h.proxyHosts.(*fakeAccessListHosts)
		hosts.hostIDs = []string{"00000000-0000-4000-8000-0000000016b1"}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h.repo.(*fakeAccessListStore).committed = cancel
		rec := callWithGrantsCtx(t, ctx, h.Delete, listWriter, http.MethodDelete, "", "id", testListID)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status %d; body %s", rec.Code, rec.Body)
		}
		want := []string{"get", "hosts", "delete", "audit deleted", "sync acl:" + testListID + " []", "regen hosts"}
		if !reflect.DeepEqual(calls.calls, want) {
			t.Errorf("calls = %v, want %v", calls.calls, want)
		}
		if !reflect.DeepEqual(hosts.bounded, []bool{true}) {
			t.Errorf("regeneration deadlines = %v, want one", hosts.bounded)
		}
	})
}

// A confirm whose client leaves while nginx applies it is stored and
// published, so it is audited all the same.
func TestAccessListConfirmDNSIsAuditedWhenTheClientLeaves(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(confirmList())
	dns.refs = []model.DNSReference{thisListUse()}
	canonical := "partner.example.com"
	dns.confirmed = model.DNSEntryStatus{Hostname: "partner.example.com", Status: model.DNSStatusOK, Addresses: []string{"203.0.113.10"},
		ObservedAddresses: []string{"203.0.113.10"}, ObservedCanonicalName: &canonical}
	dns.result = nginx.DNSApplyResult{Outcome: "accepted"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dns.confirming = cancel
	callWithGrantsCtx(t, ctx, h.ConfirmDNS, listWriter, http.MethodPost, confirmBody, "id", testListID)
	want := "audit confirmed partner.example.com [203.0.113.10] partner.example.com [acl:" + testListID + "]"
	if last := calls.calls[len(calls.calls)-1]; last != want {
		t.Errorf("calls = %v, want %q last", calls.calls, want)
	}
}

// A list without domains, before and after, leaves the DNS service alone.
func TestAccessListWithoutDomainsLeavesTheDNSServiceAlone(t *testing.T) {
	h, calls, _, _ := newDNSListHandler(&model.AccessList{ID: testListID, Name: "office", Items: []model.AccessListItem{addressRule("allow", "192.0.2.10", 0)}})
	rec := callWithGrants(t, h.Update, listWriter, http.MethodPut,
		`{"name":"office-2","items":[{"directive":"allow","address":"192.0.2.11"}]}`, "id", testListID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	if want := []string{"get", "update", "audit updated", "regen"}; !reflect.DeepEqual(calls.calls, want) {
		t.Errorf("calls = %v, want %v", calls.calls, want)
	}
}

// confirmBody is what the UI sends after showing the operator the answer.
const confirmBody = `{"hostname":"Partner.Example.com.","expected_addresses":["203.0.113.10"],"expected_canonical_name":"partner.example.com"}`

func confirmList() *model.AccessList {
	return &model.AccessList{ID: testListID, Name: "partners", Items: []model.AccessListItem{domainRule("partner.example.com", 0)}}
}

func thisListUse() model.DNSReference {
	return model.DNSReference{Scope: "acl:" + testListID, Name: "partner.example.com", OwnerID: testListID, OwnerName: "partners"}
}

// A confirm that is refused publishes nothing and records nothing.
func TestAccessListConfirmDNSRefusals(t *testing.T) {
	cases := []struct {
		name     string
		list     *model.AccessList
		body     string
		grants   permGrants
		refs     []model.DNSReference
		err      error
		status   int
		code     string
		required []string
	}{
		{"list missing", nil, confirmBody, listWriter, nil, nil, http.StatusNotFound, "", nil},
		{"domain not in the list", confirmList(), `{"hostname":"other.example.com","expected_addresses":[]}`, listWriter, nil, nil,
			http.StatusBadRequest, "not_in_list", nil},
		{"no write on this list", confirmList(), confirmBody, permGrants{"access:read": true}, []model.DNSReference{thisListUse()}, nil,
			http.StatusForbidden, "", []string{"access:write"}},
		{"also used in the global trusted list", confirmList(), confirmBody, listWriter,
			[]model.DNSReference{thisListUse(), {Scope: "trusted", Name: "partner.example.com"}}, nil,
			http.StatusForbidden, "", []string{"settings:write"}},
		{"used where no permission writes", confirmList(), confirmBody, listWriter,
			[]model.DNSReference{thisListUse(), {Scope: "uri:not-a-uuid", Name: "partner.example.com"}}, nil,
			http.StatusForbidden, "", []string{"uri:not-a-uuid"}},
		{"not waiting for review", confirmList(), confirmBody, listWriter, []model.DNSReference{thisListUse()}, dnsentry.ErrNotInReview,
			http.StatusBadRequest, "not_in_review", nil},
		{"lookup failed", confirmList(), confirmBody, listWriter, []model.DNSReference{thisListUse()}, dnsentry.ErrLookupUnavailable,
			http.StatusConflict, "lookup_unavailable", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, calls, dns, _ := newDNSListHandler(tc.list)
			dns.refs, dns.confirmErr = tc.refs, tc.err
			rec := callWithGrants(t, h.ConfirmDNS, tc.grants, http.MethodPost, tc.body, "id", testListID)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tc.status, rec.Body)
			}
			var body struct {
				Code     string   `json:"code"`
				Required []string `json:"required"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %s: %v", rec.Body, err)
			}
			if body.Code != tc.code || !reflect.DeepEqual(body.Required, tc.required) {
				t.Errorf("code %q required %v, want %q %v", body.Code, body.Required, tc.code, tc.required)
			}
			for _, call := range calls.calls {
				if strings.HasPrefix(call, "audit") || (tc.status == http.StatusForbidden && strings.HasPrefix(call, "confirm")) {
					t.Errorf("calls = %v", calls.calls)
				}
			}
		})
	}
}

// A name that answers differently now is not confirmed: the 409 carries
// what the server sees, for the dialog to show.
func TestAccessListConfirmDNSAnswersAChangedObservationWithIt(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(confirmList())
	dns.refs = []model.DNSReference{thisListUse()}
	dns.confirmErr = &dnsentry.ObservationChangedError{Observed: []string{"203.0.113.20"}, Canonical: "home.ddns.example"}
	rec := callWithGrants(t, h.ConfirmDNS, listWriter, http.MethodPost, confirmBody, "id", testListID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	var body struct {
		Code     string `json:"code"`
		Observed struct {
			Addresses     []string `json:"addresses"`
			CanonicalName *string  `json:"canonical_name"`
		} `json:"observed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "observation_changed" || !reflect.DeepEqual(body.Observed.Addresses, []string{"203.0.113.20"}) ||
		body.Observed.CanonicalName == nil || *body.Observed.CanonicalName != "home.ddns.example" {
		t.Errorf("body = %s", rec.Body)
	}
	if want := "confirm partner.example.com [203.0.113.10] partner.example.com"; !reflect.DeepEqual(calls.calls, []string{"get", want}) {
		t.Errorf("calls = %v, want the normalized name and the values the client showed", calls.calls)
	}
}

// A confirm records the server's answer and shows the name's state as this
// caller may see it.
func TestAccessListConfirmDNSAuditsAndShowsTheState(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(confirmList())
	dns.refs = []model.DNSReference{thisListUse()}
	canonical := "partner.example.com"
	dns.confirmed = model.DNSEntryStatus{Hostname: "partner.example.com", Status: model.DNSStatusOK, Addresses: []string{"203.0.113.10"},
		CanonicalName: &canonical, ObservedAddresses: []string{"203.0.113.10"}, ObservedCanonicalName: &canonical,
		Warnings: []string{model.DNSWarnBanned, model.DNSWarnCGNAT}}
	dns.result = nginx.DNSApplyResult{Outcome: "accepted"}
	rec := callWithGrants(t, h.ConfirmDNS, listWriter, http.MethodPost, confirmBody, "id", testListID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	var st model.DNSEntryStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Status != model.DNSStatusOK || !reflect.DeepEqual(st.Warnings, []string{model.DNSWarnCGNAT}) {
		t.Errorf("state = %+v, want ok without banned (no waf:read)", st)
	}
	want := "audit confirmed partner.example.com [203.0.113.10] partner.example.com [acl:" + testListID + "]"
	if last := calls.calls[len(calls.calls)-1]; last != want {
		t.Errorf("calls = %v, want %q last", calls.calls, want)
	}
}

// With domain entries switched off a confirm ends the review and publishes
// nothing: addresses is empty, and the audit still records the answer the
// operator approved, which observed_addresses holds.
func TestAccessListConfirmDNSAuditsTheApprovedAnswerWhileSwitchedOff(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(confirmList())
	dns.refs = []model.DNSReference{thisListUse()}
	canonical := "partner.example.com"
	dns.confirmed = model.DNSEntryStatus{Hostname: "partner.example.com", Status: model.DNSStatusOK, Disabled: true,
		CanonicalName: &canonical, ObservedAddresses: []string{"203.0.113.10"}, ObservedCanonicalName: &canonical}
	dns.result = nginx.DNSApplyResult{Outcome: "accepted"}
	rec := callWithGrants(t, h.ConfirmDNS, listWriter, http.MethodPost, confirmBody, "id", testListID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body %s", rec.Code, rec.Body)
	}
	want := "audit confirmed partner.example.com [203.0.113.10] partner.example.com [acl:" + testListID + "]"
	if last := calls.calls[len(calls.calls)-1]; last != want {
		t.Errorf("calls = %v, want %q last", calls.calls, want)
	}
}

// A confirm nginx refused to reload is recorded (the name is published) and
// answered 409 nginx_reload_rejected, as a list save is.
func TestAccessListConfirmDNSRefusedReloadIsAuditedAnd409(t *testing.T) {
	h, calls, dns, _ := newDNSListHandler(confirmList())
	dns.refs = []model.DNSReference{thisListUse()}
	dns.result = nginx.DNSApplyResult{Outcome: "rejected", Detail: `bind() to 0.0.0.0:18998 failed (98: Address in use)`}
	expectRefusal(t, callWithGrants(t, h.ConfirmDNS, listWriter, http.MethodPost, confirmBody, "id", testListID))
	if last := calls.calls[len(calls.calls)-1]; !strings.HasPrefix(last, "audit confirmed") {
		t.Errorf("calls = %v, want the confirm recorded", calls.calls)
	}
}

func (f *fakeAccessListHosts) AccessListUsedWithAuthProvider(context.Context, string) (string, error) {
	return "", nil
}

func (f *fakeAccessListHosts) RemoveAccessListHtpasswd(string) {}
