package service

import "testing"

func TestDDNSDesiredDiff(t *testing.T) {
	// existing managed hostnames for the host vs desired domains -> (toCreate, toDelete)
	toCreate, toDelete := ddnsDesiredDiff([]string{"a.com", "b.com"}, []string{"b.com", "c.com"})
	// desired=a,b ; existing=b,c -> create a ; delete c
	if len(toCreate) != 1 || toCreate[0] != "a.com" {
		t.Fatalf("toCreate=%v", toCreate)
	}
	if len(toDelete) != 1 || toDelete[0] != "c.com" {
		t.Fatalf("toDelete=%v", toDelete)
	}
	// disable (desired empty) -> delete all existing
	c2, d2 := ddnsDesiredDiff(nil, []string{"x.com"})
	if len(c2) != 0 || len(d2) != 1 {
		t.Fatalf("disable diff c=%v d=%v", c2, d2)
	}
}
