package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestResolveWAF_Override_UsesHostUnchanged(t *testing.T) {
	global := &model.GlobalWAF{Enabled: true, Mode: "blocking", ParanoiaLevel: 4, AnomalyThreshold: 10}
	host := &model.ProxyHost{WAFUseGlobal: false, WAFEnabled: true, WAFMode: "detection", WAFParanoiaLevel: 2, WAFAnomalyThreshold: 7}
	if got := resolveWAF(global, host); got != host {
		t.Fatalf("override should return the host pointer unchanged, got %+v", got)
	}
}

func TestResolveWAF_Inherit_UsesGlobalValues_CopyNotMutated(t *testing.T) {
	global := &model.GlobalWAF{Enabled: true, Mode: "blocking", ParanoiaLevel: 3, AnomalyThreshold: 8}
	host := &model.ProxyHost{ID: "h1", WAFUseGlobal: true, WAFEnabled: false, WAFMode: "detection", WAFParanoiaLevel: 1, WAFAnomalyThreshold: 5}
	got := resolveWAF(global, host)
	if got == host {
		t.Fatalf("inherit must return a copy, not the original host pointer")
	}
	if !got.WAFEnabled || got.WAFMode != "blocking" || got.WAFParanoiaLevel != 3 || got.WAFAnomalyThreshold != 8 {
		t.Fatalf("inherit should copy global WAF values, got %+v", got)
	}
	if got.ID != "h1" {
		t.Fatalf("inherit copy must preserve non-WAF fields, got ID %q", got.ID)
	}
	// Original must be untouched.
	if host.WAFEnabled || host.WAFMode != "detection" || host.WAFParanoiaLevel != 1 {
		t.Fatalf("original host must not be mutated, got %+v", host)
	}
}

func TestResolveWAF_Inherit_GlobalDisabled_HostGetsDisabled(t *testing.T) {
	global := &model.GlobalWAF{Enabled: false, Mode: "detection", ParanoiaLevel: 1, AnomalyThreshold: 5}
	host := &model.ProxyHost{WAFUseGlobal: true, WAFEnabled: true, WAFMode: "blocking"}
	got := resolveWAF(global, host)
	if got.WAFEnabled {
		t.Fatalf("inherit with global disabled should turn WAF off, got %+v", got)
	}
}

func TestResolveWAF_NilGlobal_ReturnsHost(t *testing.T) {
	host := &model.ProxyHost{WAFUseGlobal: true, WAFEnabled: true}
	if got := resolveWAF(nil, host); got != host {
		t.Fatalf("nil global should return the host unchanged, got %+v", got)
	}
}

func TestResolveWAF_NilHost_ReturnsNil(t *testing.T) {
	if got := resolveWAF(&model.GlobalWAF{Enabled: true}, nil); got != nil {
		t.Fatalf("nil host should return nil, got %+v", got)
	}
}

// The host list's WAF badge reads WAFEffective (#369). A host created to
// follow the global default has its own columns off, and one switched to its
// own WAF and back keeps them on; both run what the global default says.
func TestSetEffectiveWAF_ShowsWhatEachHostRuns(t *testing.T) {
	hosts := func() []model.ProxyHost {
		return []model.ProxyHost{
			{ID: "created-inheriting", WAFUseGlobal: true, WAFEnabled: false, WAFMode: "detection"},
			{ID: "back-to-inheriting", WAFUseGlobal: true, WAFEnabled: true, WAFMode: "detection"},
			{ID: "own-on", WAFUseGlobal: false, WAFEnabled: true, WAFMode: "detection"},
			{ID: "own-off", WAFUseGlobal: false, WAFEnabled: false, WAFMode: "blocking"},
		}
	}
	cases := map[string]struct {
		global *model.GlobalWAF
		want   []model.HostWAFState
	}{
		"global on": {&model.GlobalWAF{Enabled: true, Mode: "blocking"},
			[]model.HostWAFState{{Enabled: true, Mode: "blocking"}, {Enabled: true, Mode: "blocking"}, {Enabled: true, Mode: "detection"}, {Enabled: false, Mode: "blocking"}}},
		"global off": {&model.GlobalWAF{Enabled: false, Mode: "blocking"},
			[]model.HostWAFState{{Enabled: false, Mode: "blocking"}, {Enabled: false, Mode: "blocking"}, {Enabled: true, Mode: "detection"}, {Enabled: false, Mode: "blocking"}}},
	}
	for name, tc := range cases {
		list := hosts()
		setEffectiveWAF(tc.global, list)
		for i, h := range list {
			if h.WAFEffective == nil || *h.WAFEffective != tc.want[i] {
				t.Errorf("%s: %s shows %+v, want %+v", name, h.ID, h.WAFEffective, tc.want[i])
			}
		}
		if list[0].WAFEnabled || list[0].WAFMode != "detection" || !list[1].WAFEnabled {
			t.Errorf("%s: the stored columns changed: %+v", name, list[:2])
		}
	}
}
