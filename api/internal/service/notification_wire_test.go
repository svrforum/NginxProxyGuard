package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// An end-to-end pass over the emission rules and the wire format together: the
// thing an operator actually experiences is "one message, with the right body".
func TestEmitToWireOnce(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ch := &model.NotificationChannel{
		ID: "ch-1", Type: model.NotificationTypeWebhook, AllowPrivateTarget: true,
		Config: map[string]string{"url": srv.URL},
	}
	store := newFakeStore("cert.renewal_failed")
	svc := NewNotificationServiceWithStore(store)
	ctx := context.Background()

	// Four failures six hours apart, as the renewal scheduler produces.
	for i := 0; i < 4; i++ {
		_ = svc.EmitTransition(ctx, "cert.renewal_failed", "cert-1", true, "dns timeout", map[string]string{"host": "a.example.com"})
	}
	if len(store.enqueued) != 1 {
		t.Fatalf("queued %d, want 1", len(store.enqueued))
	}

	// Deliver what was queued.
	out, _, err := newWebhookAdapter().Send(ctx, ch, store.enqueued[0])
	if err != nil || out != OutcomeSent {
		t.Fatalf("out=%v err=%v", out, err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("receiver saw %d requests, want 1", len(bodies))
	}
	got := bodies[0]
	if got["event"] != "cert.renewal_failed" || got["severity"] != "error" {
		t.Fatalf("envelope = %#v", got)
	}
	fields, _ := got["fields"].(map[string]any)
	if fields["host"] != "a.example.com" || fields["detail"] != "dns timeout" {
		t.Fatalf("fields = %#v", fields)
	}
	if _, leaked := fields["raw_log"]; leaked {
		t.Fatal("raw_log reached the wire")
	}
}
