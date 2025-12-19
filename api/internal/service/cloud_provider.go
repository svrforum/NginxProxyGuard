package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"nginx-proxy-guard/internal/repository"
)

// CloudProviderIPRangesUpdatedCallback is called after IP ranges are updated
type CloudProviderIPRangesUpdatedCallback func(ctx context.Context, updatedProviders []string) error

// CloudProviderService handles cloud provider management and IP range updates
type CloudProviderService struct {
	repo               *repository.CloudProviderRepository
	httpClient         *http.Client
	stopCh             chan struct{}
	wg                 sync.WaitGroup
	mu                 sync.Mutex
	running            bool
	updateInterval     time.Duration
	onIPRangesUpdated  CloudProviderIPRangesUpdatedCallback
}

// DefaultCloudProvider represents seed data for a cloud provider
type DefaultCloudProvider struct {
	Name        string
	Slug        string
	Region      string
	Description string
	IPRangesURL string
	ASNs        []uint // ASN numbers for this provider (used when IPRangesURL is empty)
}

// Default cloud providers to seed (NO hardcoded IP ranges)
// Priority: Official URL > ASN-based extraction from MaxMind database
var defaultCloudProviders = []DefaultCloudProvider{
	// === US Providers ===
	// AWS: Official JSON API
	{Name: "Amazon Web Services", Slug: "aws", Region: "us", Description: "Amazon cloud services (EC2, Lambda, etc.)", IPRangesURL: "https://ip-ranges.amazonaws.com/ip-ranges.json", ASNs: nil},
	// Azure: No stable JSON URL (changes weekly), use ASN
	{Name: "Microsoft Azure", Slug: "azure", Region: "us", Description: "Microsoft cloud platform", IPRangesURL: "", ASNs: []uint{8075, 8068, 8069, 8070, 8071, 8072, 8073, 8074, 8076, 12076}},
	// GCP: Official JSON API
	{Name: "Google Cloud", Slug: "gcp", Region: "us", Description: "Google Cloud Platform", IPRangesURL: "https://www.gstatic.com/ipranges/cloud.json", ASNs: nil},
	// DigitalOcean: Official CSV geofeed
	{Name: "DigitalOcean", Slug: "digitalocean", Region: "us", Description: "DigitalOcean cloud hosting", IPRangesURL: "https://digitalocean.com/geo/google.csv", ASNs: []uint{14061}},
	// Linode: Official CSV geofeed
	{Name: "Linode (Akamai)", Slug: "linode", Region: "us", Description: "Linode/Akamai cloud hosting", IPRangesURL: "https://geoip.linode.com/", ASNs: []uint{63949}},
	// Oracle: Official JSON API
	{Name: "Oracle Cloud", Slug: "oracle", Region: "us", Description: "Oracle Cloud Infrastructure", IPRangesURL: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", ASNs: []uint{31898}},
	// Vultr: Official JSON geofeed
	{Name: "Vultr", Slug: "vultr", Region: "us", Description: "Vultr cloud hosting", IPRangesURL: "https://geofeed.constant.com/?json", ASNs: []uint{20473}},

	// === European Providers (ASN-based) ===
	{Name: "Contabo", Slug: "contabo", Region: "eu", Description: "German cloud hosting provider", IPRangesURL: "", ASNs: []uint{51167, 40021}},
	{Name: "Hetzner", Slug: "hetzner", Region: "eu", Description: "German hosting and cloud provider", IPRangesURL: "", ASNs: []uint{24940, 213230}},
	{Name: "OVH", Slug: "ovh", Region: "eu", Description: "French cloud provider (OVHcloud)", IPRangesURL: "", ASNs: []uint{16276}},
	{Name: "Scaleway", Slug: "scaleway", Region: "eu", Description: "French cloud provider (formerly Online.net)", IPRangesURL: "", ASNs: []uint{12876}},

	// === Chinese Providers (ASN-based) ===
	{Name: "Alibaba Cloud", Slug: "alibaba", Region: "cn", Description: "Alibaba Cloud (Aliyun)", IPRangesURL: "", ASNs: []uint{45102, 37963, 45103, 134963}},
	{Name: "Tencent Cloud", Slug: "tencent", Region: "cn", Description: "Tencent Cloud", IPRangesURL: "", ASNs: []uint{45090, 132203, 132591}},
	{Name: "Huawei Cloud", Slug: "huawei", Region: "cn", Description: "Huawei Cloud", IPRangesURL: "", ASNs: []uint{55990, 136907, 58543}},

	// === Korean Providers (ASN-based) ===
	{Name: "Smileserv (CloudV/iwinv)", Slug: "smileserv", Region: "kr", Description: "Korean cloud hosting (CloudV, iwinv)", IPRangesURL: "", ASNs: []uint{17858, 38661}},
	// Naver Cloud: AS23576 is the primary ASN (verified 2025)
	{Name: "Naver Cloud", Slug: "naver", Region: "kr", Description: "Naver Cloud Platform", IPRangesURL: "", ASNs: []uint{23576}},
	// KT Cloud: AS9947 is the cloud service ASN (NOT AS4766 which is general KT ISP)
	{Name: "KT Cloud", Slug: "kt", Region: "kr", Description: "KT Cloud (Korea Telecom IDC)", IPRangesURL: "", ASNs: []uint{9947}},
}

// NewCloudProviderService creates a new cloud provider service
func NewCloudProviderService(repo *repository.CloudProviderRepository) *CloudProviderService {
	return &CloudProviderService{
		repo: repo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		updateInterval: 24 * time.Hour, // Update daily
	}
}

// SetIPRangesUpdatedCallback sets the callback to call after IP ranges are updated
// This is used to trigger nginx config regeneration when cloud provider IPs change
func (s *CloudProviderService) SetIPRangesUpdatedCallback(cb CloudProviderIPRangesUpdatedCallback) {
	s.onIPRangesUpdated = cb
}

// SeedDefaultProviders seeds the database with default cloud providers
// Called when GeoIP is activated
func (s *CloudProviderService) SeedDefaultProviders(ctx context.Context) error {
	log.Println("[CloudProvider] Seeding default cloud providers...")

	for _, dp := range defaultCloudProviders {
		exists, err := s.repo.ExistsBySlug(ctx, dp.Slug)
		if err != nil {
			log.Printf("[CloudProvider] Error checking if %s exists: %v", dp.Slug, err)
			continue
		}

		if exists {
			// Update URL if it's different from seed data (e.g., new official URLs discovered)
			if dp.IPRangesURL != "" {
				if err := s.repo.UpdateIPRangesURL(ctx, dp.Slug, dp.IPRangesURL); err != nil {
					log.Printf("[CloudProvider] Error updating URL for %s: %v", dp.Slug, err)
				} else {
					log.Printf("[CloudProvider] Updated URL for existing provider %s", dp.Slug)
				}
			}
			continue
		}

		// Create provider with empty IP ranges
		_, err = s.repo.CreateInternal(ctx, &repository.CreateCloudProviderRequest{
			Name:        dp.Name,
			Slug:        dp.Slug,
			Region:      dp.Region,
			Description: dp.Description,
			IPRanges:    []string{},
			IPRangesURL: dp.IPRangesURL,
		})
		if err != nil {
			log.Printf("[CloudProvider] Error creating provider %s: %v", dp.Slug, err)
			continue
		}

		log.Printf("[CloudProvider] Created provider: %s", dp.Name)
	}

	// Fetch IP ranges for providers with URLs
	go func() {
		// Use a new context since the original might be cancelled
		fetchCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.UpdateAllIPRanges(fetchCtx)
	}()

	return nil
}

// Start starts the periodic IP range update scheduler
func (s *CloudProviderService) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.wg.Add(1)
	go s.run()
	log.Println("[CloudProvider Scheduler] Started")
}

// Stop stops the scheduler
func (s *CloudProviderService) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.wg.Wait()
	log.Println("[CloudProvider Scheduler] Stopped")
}

func (s *CloudProviderService) run() {
	defer s.wg.Done()

	// Initial update after a short delay
	select {
	case <-time.After(1 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		s.UpdateAllIPRanges(ctx)
		cancel()
	case <-s.stopCh:
		return
	}

	ticker := time.NewTicker(s.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			s.UpdateAllIPRanges(ctx)
			cancel()
		case <-s.stopCh:
			return
		}
	}
}

// UpdateAllIPRanges updates IP ranges for all providers
// - Providers with IPRangesURL: fetch from external API
// - Providers without URL but with ASNs: extract from MaxMind ASN database
func (s *CloudProviderService) UpdateAllIPRanges(ctx context.Context) {
	log.Println("[CloudProvider] Starting IP range update for all providers...")

	providers, err := s.repo.List(ctx)
	if err != nil {
		log.Printf("[CloudProvider] Error listing providers: %v", err)
		return
	}

	var updated, failed, skipped int
	var updatedProviders []string

	for _, p := range providers {
		var ipRanges []string
		var fetchErr error
		asns := getASNsForProvider(p.Slug)

		if p.IPRangesURL != "" {
			// Method 1: Fetch from external URL (AWS, GCP, Oracle, Vultr, Linode, DigitalOcean)
			ipRanges, fetchErr = s.fetchIPRanges(ctx, p.Slug, p.IPRangesURL)
			if fetchErr != nil {
				log.Printf("[CloudProvider] Error fetching IP ranges for %s from URL: %v", p.Slug, fetchErr)
				// Fallback to ASN if available
				if len(asns) > 0 {
					log.Printf("[CloudProvider] Falling back to ASN extraction for %s", p.Slug)
					ipRanges, fetchErr = s.extractIPRangesByASN(asns)
					if fetchErr != nil {
						log.Printf("[CloudProvider] ASN fallback also failed for %s: %v", p.Slug, fetchErr)
						failed++
						continue
					}
				} else {
					failed++
					continue
				}
			}
		} else if len(asns) > 0 {
			// Method 2: Extract from ASN database (Azure, Naver, etc.)
			ipRanges, fetchErr = s.extractIPRangesByASN(asns)
			if fetchErr != nil {
				log.Printf("[CloudProvider] Error extracting IP ranges for %s from ASN: %v", p.Slug, fetchErr)
				failed++
				continue
			}
		} else {
			// No URL and no ASN - skip
			skipped++
			continue
		}

		if len(ipRanges) == 0 {
			log.Printf("[CloudProvider] No IP ranges found for %s", p.Slug)
			skipped++
			continue
		}

		err = s.repo.UpdateIPRanges(ctx, p.Slug, ipRanges)
		if err != nil {
			log.Printf("[CloudProvider] Error updating IP ranges for %s: %v", p.Slug, err)
			failed++
			continue
		}

		log.Printf("[CloudProvider] Updated %s with %d IP ranges", p.Slug, len(ipRanges))
		updatedProviders = append(updatedProviders, p.Slug)
		updated++
	}

	log.Printf("[CloudProvider] IP range update completed: %d updated, %d failed, %d skipped", updated, failed, skipped)

	// If any providers were updated, trigger nginx config regeneration
	if len(updatedProviders) > 0 && s.onIPRangesUpdated != nil {
		log.Printf("[CloudProvider] Triggering nginx config regeneration for %d updated providers", len(updatedProviders))
		if err := s.onIPRangesUpdated(ctx, updatedProviders); err != nil {
			log.Printf("[CloudProvider] Error regenerating nginx configs: %v", err)
		}
	}
}

// fetchIPRanges fetches IP ranges from a provider's URL
func (s *CloudProviderService) fetchIPRanges(ctx context.Context, slug, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "NginxProxyGuard/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse based on provider
	switch slug {
	case "aws":
		return s.parseAWSIPRanges(body)
	case "gcp":
		return s.parseGCPIPRanges(body)
	case "oracle":
		return s.parseOracleIPRanges(body)
	case "vultr":
		return s.parseVultrGeoFeed(body)
	case "linode":
		return s.parseCSVGeoFeed(body)
	case "digitalocean":
		return s.parseCSVGeoFeed(body)
	default:
		return nil, fmt.Errorf("unknown provider format: %s", slug)
	}
}

// AWS IP Ranges JSON structure
type awsIPRanges struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"`
}

func (s *CloudProviderService) parseAWSIPRanges(data []byte) ([]string, error) {
	var aws awsIPRanges
	if err := json.Unmarshal(data, &aws); err != nil {
		return nil, fmt.Errorf("failed to parse AWS IP ranges: %w", err)
	}

	// Use a map to deduplicate
	seen := make(map[string]bool)
	var ranges []string

	for _, p := range aws.Prefixes {
		if !seen[p.IPPrefix] {
			seen[p.IPPrefix] = true
			ranges = append(ranges, p.IPPrefix)
		}
	}

	// Optionally include IPv6
	for _, p := range aws.IPv6Prefixes {
		if !seen[p.IPv6Prefix] {
			seen[p.IPv6Prefix] = true
			ranges = append(ranges, p.IPv6Prefix)
		}
	}

	return ranges, nil
}

// GCP IP Ranges JSON structure
type gcpIPRanges struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func (s *CloudProviderService) parseGCPIPRanges(data []byte) ([]string, error) {
	var gcp gcpIPRanges
	if err := json.Unmarshal(data, &gcp); err != nil {
		return nil, fmt.Errorf("failed to parse GCP IP ranges: %w", err)
	}

	seen := make(map[string]bool)
	var ranges []string

	for _, p := range gcp.Prefixes {
		if p.IPv4Prefix != "" && !seen[p.IPv4Prefix] {
			seen[p.IPv4Prefix] = true
			ranges = append(ranges, p.IPv4Prefix)
		}
		if p.IPv6Prefix != "" && !seen[p.IPv6Prefix] {
			seen[p.IPv6Prefix] = true
			ranges = append(ranges, p.IPv6Prefix)
		}
	}

	return ranges, nil
}

// Oracle IP Ranges JSON structure
type oracleIPRanges struct {
	Regions []struct {
		Region string `json:"region"`
		CIDRs  []struct {
			CIDR string `json:"cidr"`
		} `json:"cidrs"`
	} `json:"regions"`
}

func (s *CloudProviderService) parseOracleIPRanges(data []byte) ([]string, error) {
	var oracle oracleIPRanges
	if err := json.Unmarshal(data, &oracle); err != nil {
		return nil, fmt.Errorf("failed to parse Oracle IP ranges: %w", err)
	}

	seen := make(map[string]bool)
	var ranges []string

	for _, r := range oracle.Regions {
		for _, c := range r.CIDRs {
			if !seen[c.CIDR] && !strings.Contains(c.CIDR, ":") { // IPv4 only for now
				seen[c.CIDR] = true
				ranges = append(ranges, c.CIDR)
			}
		}
	}

	return ranges, nil
}

// Vultr GeoFeed JSON structure
// From https://geofeed.constant.com/?json
type vultrGeoFeed struct {
	Subnets []struct {
		IPPrefix    string `json:"ip_prefix"`
		Alpha2Code  string `json:"alpha2code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		PostalCode  string `json:"postal_code"`
	} `json:"subnets"`
}

func (s *CloudProviderService) parseVultrGeoFeed(data []byte) ([]string, error) {
	var vultr vultrGeoFeed
	if err := json.Unmarshal(data, &vultr); err != nil {
		return nil, fmt.Errorf("failed to parse Vultr geofeed: %w", err)
	}

	seen := make(map[string]bool)
	var ranges []string

	for _, subnet := range vultr.Subnets {
		if subnet.IPPrefix != "" && !seen[subnet.IPPrefix] {
			seen[subnet.IPPrefix] = true
			// Include both IPv4 and IPv6
			ranges = append(ranges, subnet.IPPrefix)
		}
	}

	return ranges, nil
}

// parseCSVGeoFeed parses RFC 8805 geofeed CSV format
// Format: ip_prefix,country_code,region_code,city,postal_code
// Used by Linode (https://geoip.linode.com/) and DigitalOcean (https://digitalocean.com/geo/google.csv)
func (s *CloudProviderService) parseCSVGeoFeed(data []byte) ([]string, error) {
	lines := strings.Split(string(data), "\n")

	seen := make(map[string]bool)
	var ranges []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split by comma - first field is the IP prefix
		fields := strings.Split(line, ",")
		if len(fields) < 1 {
			continue
		}

		ipPrefix := strings.TrimSpace(fields[0])
		if ipPrefix == "" {
			continue
		}

		// Validate it's a valid CIDR
		_, _, err := net.ParseCIDR(ipPrefix)
		if err != nil {
			continue
		}

		if !seen[ipPrefix] {
			seen[ipPrefix] = true
			ranges = append(ranges, ipPrefix)
		}
	}

	return ranges, nil
}

// HasProviders checks if any cloud providers exist
func (s *CloudProviderService) HasProviders(ctx context.Context) (bool, error) {
	providers, err := s.repo.List(ctx)
	if err != nil {
		return false, err
	}
	return len(providers) > 0, nil
}

// getASNsForProvider returns ASN numbers for a provider from seed data
func getASNsForProvider(slug string) []uint {
	for _, p := range defaultCloudProviders {
		if p.Slug == slug {
			return p.ASNs
		}
	}
	return nil
}

// ASN database path
const asnDatabasePath = "/etc/nginx/geoip/GeoLite2-ASN.mmdb"

// asnRecord represents the ASN record structure in MaxMind database
type asnRecord struct {
	AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
}

// extractIPRangesByASN extracts all IP ranges for given ASN numbers from MaxMind ASN database
func (s *CloudProviderService) extractIPRangesByASN(asns []uint) ([]string, error) {
	if len(asns) == 0 {
		return nil, nil
	}

	// Open the ASN database
	db, err := maxminddb.Open(asnDatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ASN database: %w", err)
	}
	defer db.Close()

	// Create a set of target ASNs for quick lookup
	targetASNs := make(map[uint]bool)
	for _, asn := range asns {
		targetASNs[asn] = true
	}

	// Iterate through all networks in the database
	networks := db.Networks(maxminddb.SkipAliasedNetworks)

	var ranges []string
	seen := make(map[string]bool)

	for networks.Next() {
		var record asnRecord
		subnet, err := networks.Network(&record)
		if err != nil {
			continue
		}

		// Check if this network belongs to one of our target ASNs
		if targetASNs[record.AutonomousSystemNumber] {
			cidr := subnet.String()
			if !seen[cidr] {
				seen[cidr] = true
				// Only include IPv4 for now (nginx geo module handles IPv4 better)
				if !strings.Contains(cidr, ":") {
					ranges = append(ranges, cidr)
				}
			}
		}
	}

	if err := networks.Err(); err != nil {
		return nil, fmt.Errorf("error iterating networks: %w", err)
	}

	return ranges, nil
}

// aggregateIPRanges aggregates small CIDR ranges into larger ones to reduce config size
// This is a simple implementation that merges adjacent /24 into /23, etc.
func aggregateIPRanges(ranges []string) []string {
	if len(ranges) <= 100 {
		return ranges // No need to aggregate small lists
	}

	// Parse all CIDRs into IPNet
	var nets []*net.IPNet
	for _, r := range ranges {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		nets = append(nets, ipnet)
	}

	// For simplicity, just return the original ranges
	// A more sophisticated implementation could merge adjacent networks
	// but that adds complexity and may not be necessary
	return ranges
}
