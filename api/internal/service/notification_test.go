package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// fakeStore stands in for the repository so the emission rules can be tested
// without a database. It records what would have been queued.
type fakeStore struct {
	subscribed       map[string]bool
	digestSubscribed map[string]bool
	state            map[string]string
	labels           map[string]string
	enqueued         []model.RenderedMessage
	parked           []string
}

func newFakeStore(events ...string) *fakeStore {
	f := &fakeStore{subscribed: map[string]bool{}, digestSubscribed: map[string]bool{}, state: map[string]string{}, labels: map[string]string{}}
	for _, e := range events {
		f.subscribed[e] = true
	}
	return f
}

func (f *fakeStore) TablesExist(context.Context) bool { return true }

func (f *fakeStore) GetState(_ context.Context, key, subject string) (string, error) {
	return f.state[key+"|"+subject], nil
}

func (f *fakeStore) SetState(_ context.Context, key, subject, label, state, _ string) error {
	f.state[key+"|"+subject] = state
	f.labels[key+"|"+subject] = label
	return nil
}

func (f *fakeStore) SetSubjectLabel(_ context.Context, key, subject, label string) error {
	if label != "" {
		f.labels[key+"|"+subject] = label
	}
	return nil
}

func (f *fakeStore) ChannelsForEvent(_ context.Context, key string) ([]model.NotificationChannel, error) {
	if !f.subscribed[key] {
		return nil, nil
	}
	return []model.NotificationChannel{{ID: "ch-1", Name: "test", Type: model.NotificationTypeWebhook}}, nil
}

func (f *fakeStore) ChannelsForDigestEvent(_ context.Context, key string) ([]model.NotificationChannel, error) {
	if !f.digestSubscribed[key] {
		return nil, nil
	}
	return []model.NotificationChannel{{ID: "ch-digest", Name: "summary", Type: model.NotificationTypeWebhook}}, nil
}

func (f *fakeStore) EnqueueForDigest(_ context.Context, channelID, eventKey string, _ model.RenderedMessage) error {
	f.parked = append(f.parked, channelID+"|"+eventKey)
	return nil
}

func (f *fakeStore) Enqueue(_ context.Context, _, _ string, payload model.RenderedMessage) error {
	f.enqueued = append(f.enqueued, payload)
	return nil
}

// A persistently failing certificate is re-checked every six hours. Without
// edge triggering that is four messages a day about one problem.
func TestEmitTransitionOnlyOnChange(t *testing.T) {
	fake := newFakeStore("cert.renewal_failed", "cert.renewed")
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if err := s.EmitTransition(ctx, "cert.renewal_failed", "cert-1", true, "dns timeout", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(fake.enqueued); got != 1 {
		t.Fatalf("a persistent failure produced %d messages, want 1", got)
	}

	if err := s.EmitTransition(ctx, "cert.renewal_failed", "cert-1", false, "", nil); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.enqueued); got != 2 {
		t.Fatalf("recovery produced %d total, want 2", got)
	}

	_ = s.EmitTransition(ctx, "cert.renewal_failed", "cert-1", false, "", nil)
	if got := len(fake.enqueued); got != 2 {
		t.Fatalf("a healthy re-check produced %d total, want 2", got)
	}
}

func TestEmitTransitionIsPerSubject(t *testing.T) {
	fake := newFakeStore("ddns.sync_failed")
	s := NewNotificationServiceWithStore(fake)
	_ = s.EmitTransition(context.Background(), "ddns.sync_failed", "rec-1", true, "", nil)
	_ = s.EmitTransition(context.Background(), "ddns.sync_failed", "rec-2", true, "", nil)
	if len(fake.enqueued) != 2 {
		t.Fatalf("two distinct subjects produced %d messages, want 2", len(fake.enqueued))
	}
}

// The recovery message is a different event key, so a channel that only wants
// failures does not get told about recoveries.
func TestRecoveryUsesItsOwnKey(t *testing.T) {
	fake := newFakeStore("ddns.sync_failed") // NOT subscribed to ddns.recovered
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()
	_ = s.EmitTransition(ctx, "ddns.sync_failed", "rec-1", true, "", nil)
	_ = s.EmitTransition(ctx, "ddns.sync_failed", "rec-1", false, "", nil)
	if len(fake.enqueued) != 1 {
		t.Fatalf("got %d messages, want 1 — the recovery key is not subscribed", len(fake.enqueued))
	}
}

func TestEmitBatchedCoalesces(t *testing.T) {
	fake := newFakeStore("ip.banned")
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		_ = s.EmitBatched(ctx, "ip.banned", map[string]string{"ip": "192.0.2.1"})
	}
	if len(fake.enqueued) != 0 {
		t.Fatalf("batched events enqueued immediately: %d", len(fake.enqueued))
	}
	s.FlushBatches(ctx)
	if len(fake.enqueued) != 1 {
		t.Fatalf("flush produced %d messages, want 1", len(fake.enqueued))
	}
	if c := fake.enqueued[0].Fields["count"]; c != "50" {
		t.Fatalf("count = %q, want 50", c)
	}
}

func TestFlushIsIdempotent(t *testing.T) {
	fake := newFakeStore("ip.banned")
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()
	_ = s.EmitBatched(ctx, "ip.banned", map[string]string{"ip": "192.0.2.1"})
	s.FlushBatches(ctx)
	s.FlushBatches(ctx)
	if len(fake.enqueued) != 1 {
		t.Fatalf("a second flush with nothing pending produced %d messages", len(fake.enqueued))
	}
}

// The subject is a UUID because the state must survive a rename, but nobody
// can read one. A message that says "certificate renewal failed —
// 9be4344a-60b0-4cf7-aae2-a2259ae1e2cf" tells the operator nothing about which
// site is down.
func TestMessagesNameTheHostNotTheDatabaseID(t *testing.T) {
	fake := newFakeStore("cert.renewal_failed")
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()
	const id = "9be4344a-60b0-4cf7-aae2-a2259ae1e2cf"

	_ = s.EmitTransition(ctx, "cert.renewal_failed", id, true, "DNS challenge timed out",
		map[string]string{"host": "app.example.com"})

	if len(fake.enqueued) != 1 {
		t.Fatalf("expected one message, got %d", len(fake.enqueued))
	}
	msg := fake.enqueued[0]
	body := plainText("en", msg)
	if strings.Contains(body, id) {
		t.Errorf("the raw id reached the message:\n%s", body)
	}
	if !strings.Contains(body, "app.example.com") {
		t.Errorf("the message does not name the host:\n%s", body)
	}
	// The domain arrives once. It is the host, and repeating it as the subject
	// would print the same value on two lines.
	if strings.Count(body, "app.example.com") != 1 {
		t.Errorf("the host is repeated:\n%s", body)
	}
	// The state still keys on the id — that is what makes it survive a rename.
	if got, _ := fake.GetState(ctx, "cert.renewal_failed", id); got != "failing" {
		t.Errorf("state should still be keyed by id, got %q", got)
	}
	if fake.labels["cert.renewal_failed|"+id] != "app.example.com" {
		t.Errorf("label not persisted: %q", fake.labels["cert.renewal_failed|"+id])
	}
}

// A row written before labels existed gets its name back on the next check,
// which is the only time a week-long failure is looked at again.
func TestAnUnchangedFailureStillLearnsItsLabel(t *testing.T) {
	fake := newFakeStore("cert.renewal_failed")
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()
	const id = "cert-1"
	fake.state["cert.renewal_failed|"+id] = "failing" // as an older version left it

	_ = s.EmitTransition(ctx, "cert.renewal_failed", id, true, "still failing",
		map[string]string{"host": "app.example.com"})

	if len(fake.enqueued) != 0 {
		t.Fatalf("an unchanged state must not re-announce, got %d messages", len(fake.enqueued))
	}
	if fake.labels["cert.renewal_failed|"+id] != "app.example.com" {
		t.Errorf("label was not backfilled: %q", fake.labels["cert.renewal_failed|"+id])
	}
}

// "Summary only" is the middle state an operator picks for a noisy event. It
// used to remove the key from `events` and be read by nothing, so it was an
// elaborate spelling of "off" — the event went nowhere at all.
func TestSummaryOnlyParksTheEventInsteadOfDroppingIt(t *testing.T) {
	fake := newFakeStore() // NOT subscribed for immediate delivery
	fake.digestSubscribed["ip.banned"] = true
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()

	_ = s.EmitBatched(ctx, "ip.banned", map[string]string{"ip": "192.0.2.1"})
	s.FlushBatches(ctx)

	if len(fake.enqueued) != 0 {
		t.Errorf("a summary-only event was delivered immediately: %d", len(fake.enqueued))
	}
	if len(fake.parked) != 1 || fake.parked[0] != "ch-digest|ip.banned" {
		t.Errorf("the event was not parked for the summary: %v", fake.parked)
	}
}

// A channel can want one event immediately and another in the summary, and both
// must happen for the same emission.
func TestImmediateAndSummaryChannelsBothGetTheEvent(t *testing.T) {
	fake := newFakeStore("cert.renewal_failed")
	fake.digestSubscribed["cert.renewal_failed"] = true
	s := NewNotificationServiceWithStore(fake)

	_ = s.EmitTransition(context.Background(), "cert.renewal_failed", "cert-1", true, "boom",
		map[string]string{"host": "app.example.com"})

	if len(fake.enqueued) != 1 {
		t.Errorf("immediate channel got %d messages, want 1", len(fake.enqueued))
	}
	if len(fake.parked) != 1 {
		t.Errorf("summary channel parked %d items, want 1", len(fake.parked))
	}
}

func TestNoChannelsMeansNoWork(t *testing.T) {
	fake := newFakeStore() // subscribes to nothing
	s := NewNotificationServiceWithStore(fake)
	_ = s.EmitTransition(context.Background(), "cert.renewal_failed", "cert-1", true, "boom", nil)
	if len(fake.enqueued) != 0 {
		t.Fatalf("enqueued %d with no subscribed channel", len(fake.enqueued))
	}
	// The state is still recorded, so a later subscription does not immediately
	// re-announce a failure that has been going on for days.
	if got, _ := fake.GetState(context.Background(), "cert.renewal_failed", "cert-1"); got != "failing" {
		t.Fatalf("state = %q, want failing", got)
	}
}

// A payload must never carry the fields that hold credentials.
func TestPayloadCarriesNoSensitiveFields(t *testing.T) {
	fake := newFakeStore("ip.banned")
	s := NewNotificationServiceWithStore(fake)
	ctx := context.Background()
	_ = s.EmitBatched(ctx, "ip.banned", map[string]string{
		"ip": "192.0.2.1", "raw_log": "SECRET", "rule_data": "SECRET",
		"user_agent": "SECRET", "request_uri": "SECRET", "headers": "SECRET",
	})
	s.FlushBatches(ctx)
	if len(fake.enqueued) != 1 {
		t.Fatal("nothing enqueued")
	}
	for _, banned := range []string{"raw_log", "rule_data", "user_agent", "request_uri", "headers"} {
		if v, ok := fake.enqueued[0].Fields[banned]; ok {
			t.Errorf("payload leaked %s = %q", banned, v)
		}
	}
	if fake.enqueued[0].Fields["ip"] != "192.0.2.1" {
		t.Error("allowed field was dropped")
	}
}

func TestEmitIsNoOpWithoutTables(t *testing.T) {
	s := NewNotificationServiceWithStore(&noTablesStore{})
	if err := s.EmitTransition(context.Background(), "cert.renewal_failed", "c", true, "", nil); err != nil {
		t.Fatalf("a missing schema must be a no-op, got %v", err)
	}
}

type noTablesStore struct{ fakeStore }

func (n *noTablesStore) TablesExist(context.Context) bool { return false }

var _ = time.Second
