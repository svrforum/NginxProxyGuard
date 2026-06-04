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

	// identical sets -> both empty
	c3, d3 := ddnsDesiredDiff([]string{"a.com", "b.com"}, []string{"a.com", "b.com"})
	if len(c3) != 0 || len(d3) != 0 {
		t.Fatalf("identical diff c=%v d=%v", c3, d3)
	}

	// pure additions (nothing existing) -> create all, delete none
	c4, d4 := ddnsDesiredDiff([]string{"a.com", "b.com"}, nil)
	if len(c4) != 2 || len(d4) != 0 {
		t.Fatalf("additions diff c=%v d=%v", c4, d4)
	}

	// pure deletions (nothing desired) -> create none, delete all
	c5, d5 := ddnsDesiredDiff(nil, []string{"a.com", "b.com"})
	if len(c5) != 0 || len(d5) != 2 {
		t.Fatalf("deletions diff c=%v d=%v", c5, d5)
	}

	// duplicate entries in desired -> deduped, single create, no spurious delete
	c6, d6 := ddnsDesiredDiff([]string{"a.com", "a.com"}, nil)
	if len(c6) != 1 || c6[0] != "a.com" || len(d6) != 0 {
		t.Fatalf("duplicate-desired diff c=%v d=%v", c6, d6)
	}
}
