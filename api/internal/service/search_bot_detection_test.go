package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

// $is_search_bot feeds three toggles: the bot filter's "allow search
// engines" and the "allow search bots" of geo restriction and cloud blocking.
func TestSearchBotDetectionNeeded(t *testing.T) {
	ranges := []string{"198.51.100.0/24"}
	for _, tc := range []struct {
		name string
		d    nginx.ProxyHostConfigData
		want bool
	}{
		{"nothing", nginx.ProxyHostConfigData{}, false},
		{"bot filter allows search engines", nginx.ProxyHostConfigData{BotFilter: &model.BotFilter{Enabled: true, AllowSearchEngines: true}}, true},
		{"bot filter without search engines", nginx.ProxyHostConfigData{BotFilter: &model.BotFilter{Enabled: true}}, false},
		{"bot filter disabled", nginx.ProxyHostConfigData{BotFilter: &model.BotFilter{Enabled: false, AllowSearchEngines: true}}, false},
		{"geo allows search bots, no bot filter", nginx.ProxyHostConfigData{GeoRestriction: &model.GeoRestriction{Enabled: true, AllowSearchBots: true}}, true},
		{"geo disabled", nginx.ProxyHostConfigData{GeoRestriction: &model.GeoRestriction{Enabled: false, AllowSearchBots: true}}, false},
		{"geo without search bots", nginx.ProxyHostConfigData{GeoRestriction: &model.GeoRestriction{Enabled: true}}, false},
		{"cloud allows search bots", nginx.ProxyHostConfigData{BlockedCloudIPRanges: ranges, CloudProviderAllowSearchBots: true}, true},
		{"cloud toggle without ranges", nginx.ProxyHostConfigData{CloudProviderAllowSearchBots: true}, false},
		{"cloud ranges without the toggle", nginx.ProxyHostConfigData{BlockedCloudIPRanges: ranges}, false},
	} {
		if got := searchBotDetectionNeeded(&tc.d); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A host whose geo restriction allows search bots but which has no bot filter.
// The search-engine list used to be loaded only for the bot filter, so the
// config never recognised a search bot and the toggle did nothing: crawlers
// were challenged (challenge mode) or got 403 (block mode) like everyone else.
func TestGeoAllowSearchBotsWorksWithoutBotFilter(t *testing.T) {
	const hostID = "00000000-0000-4000-8000-0000000000e9"
	for _, challenge := range []bool{true, false} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
		mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(hostID).
			WillReturnRows(sqlmock.NewRows(positionalColumns(12)).AddRow(
				"00000000-0000-4000-8000-0000000000ea", hostID, "whitelist", "{KR}", "{}", true,
				challenge, false, true, false, now, now)) // challenge_mode, private IPs, search bots, disable_global
		s := &ProxyHostService{geoRepo: repository.NewGeoRepository(&database.DB{DB: db})}
		host := &model.ProxyHost{ID: hostID, DomainNames: []string{"bots.example.com"}, ForwardScheme: "http",
			ForwardHost: "192.0.2.10", ForwardPort: 8080, Enabled: true}

		data, err := s.getHostConfigData(context.Background(), host)
		db.Close()
		if err != nil {
			t.Fatalf("challenge=%v: getHostConfigData: %v", challenge, err)
		}
		if !strings.Contains(data.SearchEnginesList, "Googlebot") {
			t.Fatalf("challenge=%v: no search-engine list for a host that allows search bots: %q", challenge, data.SearchEnginesList)
		}

		dir := t.TempDir()
		m := nginx.NewManager(filepath.Join(dir, "conf.d"), filepath.Join(dir, "certs"))
		if err := m.GenerateConfigFull(context.Background(), data); err != nil {
			t.Fatalf("challenge=%v: render: %v", challenge, err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "conf.d", nginx.GetConfigFilename(host)))
		if err != nil {
			t.Fatal(err)
		}
		out := string(b)
		bypass := "if ($is_search_bot = 1) {\n        set $geo_blocked 0;" // challenge mode
		if !challenge {
			bypass = "if ($is_search_bot = 1) {\n        set $geo_block_check \"\";"
		}
		for _, want := range []string{"set $is_search_bot 1;", bypass} {
			if !strings.Contains(out, want) {
				t.Errorf("challenge=%v: config lacks %q", challenge, want)
			}
		}
	}
}
