package service

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver struct {
	ip  string
	err error
}

func (f fakeResolver) ResolveContainerIP(ctx context.Context, name string) (string, error) {
	return f.ip, f.err
}

func TestApplyContainerTarget(t *testing.T) {
	s := &ProxyHostService{}
	// nil name → forwardHost unchanged, no resolver needed
	if got, err := s.applyContainerTarget(context.Background(), nil, "1.2.3.4"); err != nil || got != "1.2.3.4" {
		t.Fatalf("nil name: got (%q,%v) want (1.2.3.4,nil)", got, err)
	}
	// name set + resolver success → resolved IP
	s.containerResolver = fakeResolver{ip: "172.18.0.5"}
	name := "myapp"
	if got, err := s.applyContainerTarget(context.Background(), &name, ""); err != nil || got != "172.18.0.5" {
		t.Fatalf("resolve ok: got (%q,%v) want (172.18.0.5,nil)", got, err)
	}
	// name set + resolver error → error
	s.containerResolver = fakeResolver{err: errors.New("not found")}
	if _, err := s.applyContainerTarget(context.Background(), &name, ""); err == nil {
		t.Fatalf("resolve fail: expected error")
	}
}
