package service

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

func TestProxyHostTester_TestHost_StreamTCP(t *testing.T) {
	listener, port := startTCPListener(t)

	host := &model.ProxyHost{
		ProxyType:        model.ProxyTypeStream,
		DomainNames:      pq.StringArray{"postgres.example.test"},
		ForwardHost:      "db.internal",
		ForwardPort:      5432,
		StreamListenHost: "127.0.0.1",
		StreamListenPort: port,
		StreamProtocol:   model.StreamProtocolTCP,
		StreamSSLPreread: true,
	}

	result, err := NewProxyHostTester().TestHost(context.Background(), host, "")
	if err != nil {
		t.Fatalf("TestHost returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected stream listener test to succeed, got error %q", result.Error)
	}
	if result.Stream == nil {
		t.Fatal("expected stream test details")
	}
	if result.Stream.Protocol != model.StreamProtocolTCP {
		t.Fatalf("expected tcp protocol, got %q", result.Stream.Protocol)
	}
	if result.Stream.TargetAddress != listener.Addr().String() {
		t.Fatalf("expected target %q, got %q", listener.Addr().String(), result.Stream.TargetAddress)
	}
	if result.HTTP != nil || result.SSL != nil || result.Cache != nil || result.Security != nil {
		t.Fatal("stream test should not populate HTTP-only result sections")
	}
}

func TestProxyHostTester_TestUpstream_StreamTCP(t *testing.T) {
	listener, port := startTCPListener(t)
	host, _, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	result, err := NewProxyHostTester().TestUpstream(context.Background(), &model.ProxyHost{
		ProxyType:      model.ProxyTypeStream,
		DomainNames:    pq.StringArray{"tcp-service"},
		ForwardHost:    host,
		ForwardPort:    port,
		StreamProtocol: model.StreamProtocolTCP,
	})
	if err != nil {
		t.Fatalf("TestUpstream returned error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected stream upstream test to succeed, got error %q", result.Error)
	}
	if result.Domain != listener.Addr().String() {
		t.Fatalf("expected result domain %q, got %q", listener.Addr().String(), result.Domain)
	}
	if result.Stream == nil || result.Stream.UpstreamAddress != listener.Addr().String() {
		t.Fatalf("expected upstream address %q, got %#v", listener.Addr().String(), result.Stream)
	}
}

func startTCPListener(t *testing.T) (net.Listener, int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}

	return listener, port
}
