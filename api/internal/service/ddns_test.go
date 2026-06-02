package service

import (
	"context"
	"encoding/json"
	"testing"

	"nginx-proxy-guard/internal/model"
)

type fakeUpdater struct{ calls int }

func (f *fakeUpdater) Update(ctx context.Context, rec model.DDNSRecord, c json.RawMessage, ip string) error {
	f.calls++
	return nil
}

func TestNeedsUpdate(t *testing.T) {
	// already ok + same IP -> skip
	if needsUpdate(model.DDNSRecord{LastIP: "1.1.1.1", LastStatus: model.DDNSStatusOK}, "1.1.1.1") {
		t.Fatal("should skip when ip unchanged and last status ok")
	}
	// changed IP -> update
	if !needsUpdate(model.DDNSRecord{LastIP: "1.1.1.1", LastStatus: model.DDNSStatusOK}, "2.2.2.2") {
		t.Fatal("should update on ip change")
	}
	// previous error -> retry even if same IP
	if !needsUpdate(model.DDNSRecord{LastIP: "1.1.1.1", LastStatus: model.DDNSStatusError}, "1.1.1.1") {
		t.Fatal("should retry after error")
	}
}
