package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

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
