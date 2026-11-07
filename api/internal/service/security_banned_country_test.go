package service

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

type fakeCountries map[string]*GeoIPInfo

func (f fakeCountries) LookupWithContext(_ context.Context, ip string) *GeoIPInfo { return f[ip] }

// The banned IP list says where each address is (#369). A range or an
// address GeoIP does not know stays without a country, and so does every
// address when no GeoIP database is installed.
func TestBannedIPListShowsCountries(t *testing.T) {
	bans := []model.BannedIP{{IPAddress: "192.0.2.10"}, {IPAddress: "192.0.2.0/24"}, {IPAddress: "198.51.100.7"}}
	s := &SecurityService{geo: fakeCountries{"192.0.2.10": {CountryCode: "KR", Country: "South Korea"}}}
	s.setBannedCountries(context.Background(), bans)
	if bans[0].CountryCode != "KR" || bans[0].Country != "South Korea" {
		t.Errorf("known address: %+v", bans[0])
	}
	if bans[1].CountryCode != "" || bans[2].CountryCode != "" {
		t.Errorf("a range and an unknown address got a country: %+v %+v", bans[1], bans[2])
	}

	none := &SecurityService{}
	none.SetGeoIP(nil)
	none.setBannedCountries(context.Background(), bans[1:])
}
