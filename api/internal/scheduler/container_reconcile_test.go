package scheduler

import "testing"

func TestIPChanged(t *testing.T) {
	if !ipChanged("172.18.0.5", "172.18.0.9") {
		t.Fatal("different IPs must be a change")
	}
	if ipChanged("172.18.0.5", "172.18.0.5") {
		t.Fatal("same IP must not be a change")
	}
	if ipChanged("172.18.0.5", "") {
		t.Fatal("empty new IP (resolve fail) must NOT trigger regen")
	}
}
