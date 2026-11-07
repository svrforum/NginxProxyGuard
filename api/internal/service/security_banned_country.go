package service

import (
	"context"

	"nginx-proxy-guard/internal/model"
)

// countryLooker is GeoIPService as the banned IP list uses it.
type countryLooker interface {
	LookupWithContext(ctx context.Context, ipStr string) *GeoIPInfo
}

// SetGeoIP lets the banned IP list say where each address is (#369).
func (s *SecurityService) SetGeoIP(geo *GeoIPService) {
	if geo != nil {
		s.geo = geo
	}
}

// setBannedCountries fills in each banned address's country from GeoIP. A
// range, a private address, or no GeoIP database leaves it empty. A lookup
// reads the database in memory, so a page of bans costs microseconds.
func (s *SecurityService) setBannedCountries(ctx context.Context, bans []model.BannedIP) {
	if s.geo == nil {
		return
	}
	for i := range bans {
		if info := s.geo.LookupWithContext(ctx, bans[i].IPAddress); info != nil {
			bans[i].CountryCode, bans[i].Country = info.CountryCode, info.Country
		}
	}
}
