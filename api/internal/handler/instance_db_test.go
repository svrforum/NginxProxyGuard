package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// The instance name is saved trimmed, a name that is too long is refused and
// leaves the saved one, and the header reads it from GET /api/v1/instance
// with no permission at all (#369).
func TestInstanceNameAgainstTheDatabase(t *testing.T) {
	db := openSystemSettingsDB(t)
	settings := repository.NewSystemSettingsRepository(db)
	h := &SystemSettingsHandler{repo: settings, audit: service.NewAuditService(repository.NewAuditLogRepository(db))}
	admin := permGrants{"settings:read": true, "settings:write": true}
	put := func(body string) int {
		return callWithGrants(t, h.UpdateSystemSettings, admin, http.MethodPut, body).Code
	}
	header := func() model.InstanceInfo {
		t.Helper()
		rec := callWithGrants(t, NewInstanceHandler(settings, nil).Get, permGrants{}, http.MethodGet, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /instance: %d %s", rec.Code, rec.Body)
		}
		var info model.InstanceInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		return info
	}

	if got := header(); got != (model.InstanceInfo{Version: config.AppVersion}) {
		t.Fatalf("a new install's header: %+v", got)
	}
	if code := put(`{"instance_name":"  home lab  "}`); code != http.StatusOK {
		t.Fatalf("save: %d", code)
	}
	if got := header().InstanceName; got != "home lab" {
		t.Fatalf("the header shows %q, want the name trimmed", got)
	}
	if code := put(`{"instance_name":"` + strings.Repeat("x", 33) + `"}`); code != http.StatusBadRequest {
		t.Fatalf("33 characters: %d, want 400", code)
	}
	if got := header().InstanceName; got != "home lab" {
		t.Fatalf("a refused name replaced the saved one: %q", got)
	}
	if code := put(`{"instance_name":""}`); code != http.StatusOK || header().InstanceName != "" {
		t.Fatalf("clearing the name: %d, header %q", code, header().InstanceName)
	}
}
