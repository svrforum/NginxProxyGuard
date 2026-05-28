package service

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver struct {
	ip         string
	err        error
	gotName    string
	gotNetwork string
	callCount  int
}

func (f *fakeResolver) ResolveContainerIP(ctx context.Context, name string, network string) (string, error) {
	f.gotName = name
	f.gotNetwork = network
	f.callCount++
	return f.ip, f.err
}

func TestApplyContainerTarget(t *testing.T) {
	s := &ProxyHostService{}
	// nil name → forwardHost unchanged, no resolver needed
	if got, err := s.applyContainerTarget(context.Background(), nil, nil, "1.2.3.4"); err != nil || got != "1.2.3.4" {
		t.Fatalf("nil name: got (%q,%v) want (1.2.3.4,nil)", got, err)
	}
	// name set + resolver success → resolved IP
	fake := &fakeResolver{ip: "172.18.0.5"}
	s.containerResolver = fake
	name := "myapp"
	if got, err := s.applyContainerTarget(context.Background(), &name, nil, ""); err != nil || got != "172.18.0.5" {
		t.Fatalf("resolve ok: got (%q,%v) want (172.18.0.5,nil)", got, err)
	}
	if fake.gotNetwork != "" {
		t.Fatalf("nil network must pass empty string to resolver, got %q", fake.gotNetwork)
	}
	// network supplied → forwarded to resolver verbatim
	net := "bebe"
	fake.ip = "172.24.0.4"
	if got, err := s.applyContainerTarget(context.Background(), &name, &net, ""); err != nil || got != "172.24.0.4" {
		t.Fatalf("resolve with network: got (%q,%v) want (172.24.0.4,nil)", got, err)
	}
	if fake.gotNetwork != "bebe" {
		t.Fatalf("network argument lost: got %q want bebe", fake.gotNetwork)
	}
	// name set + resolver error → error
	s.containerResolver = &fakeResolver{err: errors.New("not found")}
	if _, err := s.applyContainerTarget(context.Background(), &name, nil, ""); err == nil {
		t.Fatalf("resolve fail: expected error")
	}
}
