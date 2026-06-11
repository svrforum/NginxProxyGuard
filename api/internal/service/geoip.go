package service

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"

	"nginx-proxy-guard/pkg/cache"
)

// GeoIPInfo contains location information for an IP address
type GeoIPInfo struct {
	Country     string
	CountryCode string
	City        string
	ASN         string
	Org         string
}

// GeoIPService provides IP geolocation lookups
type GeoIPService struct {
	countryDB  *geoip2.Reader
	asnDB      *geoip2.Reader
	mu         sync.RWMutex
	enabled    bool
	redisCache *cache.RedisClient
}

// NewGeoIPService creates a new GeoIP service
func NewGeoIPService() *GeoIPService {
	s := &GeoIPService{}
	s.LoadDatabases()
	return s
}

// NewGeoIPServiceWithCache creates a new GeoIP service with cache support
func NewGeoIPServiceWithCache(redisCache *cache.RedisClient) *GeoIPService {
	s := &GeoIPService{
		redisCache: redisCache,
	}
	s.LoadDatabases()
	return s
}

// SetCache sets the cache client
func (s *GeoIPService) SetCache(redisCache *cache.RedisClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redisCache = redisCache
}

// LoadDatabases loads or reloads the GeoIP databases
func (s *GeoIPService) LoadDatabases() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close existing databases
	if s.countryDB != nil {
		s.countryDB.Close()
		s.countryDB = nil
	}
	if s.asnDB != nil {
		s.asnDB.Close()
		s.asnDB = nil
	}

	s.enabled = false

	// Try to open Country database
	countryDB, err := geoip2.Open("/etc/nginx/geoip/GeoLite2-Country.mmdb")
	if err != nil {
		log.Printf("GeoIP: Country database not available: %v", err)
	} else {
		s.countryDB = countryDB
		log.Println("GeoIP: Country database loaded successfully")
	}

	// Try to open ASN database
	asnDB, err := geoip2.Open("/etc/nginx/geoip/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Printf("GeoIP: ASN database not available: %v", err)
	} else {
		s.asnDB = asnDB
		log.Println("GeoIP: ASN database loaded successfully")
	}

	s.enabled = s.countryDB != nil
}

// Close closes the GeoIP databases
func (s *GeoIPService) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.countryDB != nil {
		s.countryDB.Close()
		s.countryDB = nil
	}
	if s.asnDB != nil {
		s.asnDB.Close()
		s.asnDB = nil
	}
	s.enabled = false
}

// IsEnabled returns whether GeoIP lookups are available
func (s *GeoIPService) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// Lookup returns GeoIP information for an IP address
func (s *GeoIPService) Lookup(ipStr string) *GeoIPInfo {
	return s.LookupWithContext(context.Background(), ipStr)
}

// LookupWithContext returns GeoIP information for an IP address.
// The lookup reads the in-process mmap'd mmdb databases directly (~µs).
// The old Valkey cache in front of it cost 1-2 network round trips plus two
// JSON codec passes per log line — orders of magnitude slower than the lookup
// it fronted — so it was removed (nothing else read or wrote that cache key).
func (s *GeoIPService) LookupWithContext(ctx context.Context, ipStr string) *GeoIPInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Skip private/local IPs
	if isPrivateIP(ip) {
		return nil
	}

	// Perform actual lookup
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.enabled {
		return nil
	}

	info := &GeoIPInfo{}

	// Lookup country
	if s.countryDB != nil {
		record, err := s.countryDB.Country(ip)
		if err == nil && record.Country.IsoCode != "" {
			info.CountryCode = record.Country.IsoCode
			// Get country name in English
			if name, ok := record.Country.Names["en"]; ok {
				info.Country = name
			} else if name, ok := record.Country.Names["ko"]; ok {
				info.Country = name
			}
		}
	}

	// Lookup ASN
	if s.asnDB != nil {
		record, err := s.asnDB.ASN(ip)
		if err == nil {
			if record.AutonomousSystemNumber > 0 {
				info.ASN = formatASN(record.AutonomousSystemNumber)
			}
			info.Org = record.AutonomousSystemOrganization
		}
	}

	// Only return info if we got something
	if info.CountryCode == "" && info.ASN == "" {
		return nil
	}

	return info
}

// isPrivateIP checks if an IP is private/local
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for docker bridge networks (172.16-31.x.x)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
	}

	return false
}

// formatASN formats an ASN number
func formatASN(asn uint) string {
	if asn == 0 {
		return ""
	}
	return "AS" + itoa(asn)
}

// itoa converts uint to string without fmt
func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
