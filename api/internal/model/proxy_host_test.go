package model

import "testing"

func TestNormalizeProxyType(t *testing.T) {
	// Backup import compatibility: pre-v2.18.0 backups have no proxy_type
	// column, so the JSON unmarshals to an empty string. NormalizeProxyType
	// MUST coerce empty → "http" or the NOT NULL constraint blows up on
	// import. Lock this contract.
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: ProxyTypeHTTP},
		{in: " ", want: ProxyTypeHTTP},
		{in: "http", want: ProxyTypeHTTP},
		{in: "HTTP", want: ProxyTypeHTTP},
		{in: "stream", want: ProxyTypeStream},
		{in: "STREAM", want: ProxyTypeStream},
		{in: "Stream", want: ProxyTypeStream},
		{in: "garbage", want: ProxyTypeHTTP},
	}
	for _, tc := range cases {
		if got := NormalizeProxyType(tc.in); got != tc.want {
			t.Errorf("NormalizeProxyType(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeStreamProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: StreamProtocolTCP},
		{in: "tcp", want: StreamProtocolTCP},
		{in: "TCP", want: StreamProtocolTCP},
		{in: "udp", want: StreamProtocolUDP},
		{in: "UDP", want: StreamProtocolUDP},
		{in: "garbage", want: StreamProtocolTCP},
	}
	for _, tc := range cases {
		if got := NormalizeStreamProtocol(tc.in); got != tc.want {
			t.Errorf("NormalizeStreamProtocol(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
