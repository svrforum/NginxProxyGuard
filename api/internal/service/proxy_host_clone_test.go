package service

import "testing"

func sp(s string) *string { return &s }

func TestResolveCloneContainerBinding(t *testing.T) {
	srcName, srcNet := sp("oldc"), sp("oldnet")

	n, net := resolveCloneContainerBinding(srcName, srcNet, sp("newc"), sp("newnet"), "1.2.3.4")
	if n == nil || *n != "newc" || net == nil || *net != "newnet" {
		t.Fatalf("explicit container: got %v/%v", n, net)
	}
	n, net = resolveCloneContainerBinding(srcName, srcNet, nil, nil, "1.2.3.4")
	if n != nil || net != nil {
		t.Fatalf("host override clear: got %v/%v", n, net)
	}
	n, net = resolveCloneContainerBinding(srcName, srcNet, nil, nil, "")
	if n != srcName || net != srcNet {
		t.Fatalf("copy source: got %v/%v", n, net)
	}
	n, net = resolveCloneContainerBinding(srcName, srcNet, sp("newc"), nil, "1.2.3.4")
	if n == nil || *n != "newc" || net != nil {
		t.Fatalf("container nil net: got %v/%v", n, net)
	}
}
