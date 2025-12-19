package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

type CloudProviderRepository struct {
	db *sql.DB
}

func NewCloudProviderRepository(db *sql.DB) *CloudProviderRepository {
	return &CloudProviderRepository{db: db}
}

// List returns all cloud providers
func (r *CloudProviderRepository) List(ctx context.Context) ([]model.CloudProvider, error) {
	query := `
		SELECT id, name, slug, region, COALESCE(description, ''), ip_ranges,
		       COALESCE(ip_ranges_url, ''), last_updated, enabled, created_at, updated_at
		FROM cloud_providers
		ORDER BY region, name`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list cloud providers: %w", err)
	}
	defer rows.Close()

	var providers []model.CloudProvider
	for rows.Next() {
		var p model.CloudProvider
		var lastUpdated sql.NullTime
		err := rows.Scan(
			&p.ID, &p.Name, &p.Slug, &p.Region, &p.Description,
			pq.Array(&p.IPRanges), &p.IPRangesURL, &lastUpdated,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan cloud provider: %w", err)
		}
		if lastUpdated.Valid {
			p.LastUpdated = &lastUpdated.Time
		}
		providers = append(providers, p)
	}

	return providers, nil
}

// ListByRegion returns providers grouped by region
func (r *CloudProviderRepository) ListByRegion(ctx context.Context) (*model.CloudProvidersByRegion, error) {
	query := `
		SELECT slug, name, region, COALESCE(description, ''), array_length(ip_ranges, 1), enabled
		FROM cloud_providers
		WHERE enabled = true
		ORDER BY region, name`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list cloud providers: %w", err)
	}
	defer rows.Close()

	result := &model.CloudProvidersByRegion{
		US: []model.CloudProviderSummary{},
		EU: []model.CloudProviderSummary{},
		CN: []model.CloudProviderSummary{},
		KR: []model.CloudProviderSummary{},
	}

	for rows.Next() {
		var s model.CloudProviderSummary
		var ipCount sql.NullInt64
		err := rows.Scan(&s.Slug, &s.Name, &s.Region, &s.Description, &ipCount, &s.Enabled)
		if err != nil {
			return nil, fmt.Errorf("failed to scan cloud provider: %w", err)
		}
		if ipCount.Valid {
			s.IPCount = int(ipCount.Int64)
		}

		switch s.Region {
		case "us":
			result.US = append(result.US, s)
		case "eu":
			result.EU = append(result.EU, s)
		case "cn":
			result.CN = append(result.CN, s)
		case "kr":
			result.KR = append(result.KR, s)
		}
	}

	return result, nil
}

// GetBySlug returns a cloud provider by slug
func (r *CloudProviderRepository) GetBySlug(ctx context.Context, slug string) (*model.CloudProvider, error) {
	query := `
		SELECT id, name, slug, region, COALESCE(description, ''), ip_ranges,
		       COALESCE(ip_ranges_url, ''), last_updated, enabled, created_at, updated_at
		FROM cloud_providers
		WHERE slug = $1`

	var p model.CloudProvider
	var lastUpdated sql.NullTime
	err := r.db.QueryRowContext(ctx, query, slug).Scan(
		&p.ID, &p.Name, &p.Slug, &p.Region, &p.Description,
		pq.Array(&p.IPRanges), &p.IPRangesURL, &lastUpdated,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cloud provider: %w", err)
	}
	if lastUpdated.Valid {
		p.LastUpdated = &lastUpdated.Time
	}

	return &p, nil
}

// Create creates a new cloud provider
func (r *CloudProviderRepository) Create(ctx context.Context, req *model.CreateCloudProviderRequest) (*model.CloudProvider, error) {
	query := `
		INSERT INTO cloud_providers (name, slug, region, description, ip_ranges, ip_ranges_url)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, slug, region, description, ip_ranges, ip_ranges_url, last_updated, enabled, created_at, updated_at`

	var p model.CloudProvider
	var lastUpdated sql.NullTime
	var desc, url sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		req.Name, req.Slug, req.Region, req.Description, pq.Array(req.IPRanges), req.IPRangesURL,
	).Scan(
		&p.ID, &p.Name, &p.Slug, &p.Region, &desc,
		pq.Array(&p.IPRanges), &url, &lastUpdated,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud provider: %w", err)
	}

	p.Description = desc.String
	p.IPRangesURL = url.String
	if lastUpdated.Valid {
		p.LastUpdated = &lastUpdated.Time
	}

	return &p, nil
}

// Update updates an existing cloud provider
func (r *CloudProviderRepository) Update(ctx context.Context, slug string, req *model.UpdateCloudProviderRequest) (*model.CloudProvider, error) {
	// Build dynamic update query
	var sets []string
	var args []interface{}
	argNum := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argNum))
		args = append(args, *req.Name)
		argNum++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argNum))
		args = append(args, *req.Description)
		argNum++
	}
	if req.IPRanges != nil {
		sets = append(sets, fmt.Sprintf("ip_ranges = $%d", argNum))
		args = append(args, pq.Array(*req.IPRanges))
		argNum++
	}
	if req.IPRangesURL != nil {
		sets = append(sets, fmt.Sprintf("ip_ranges_url = $%d", argNum))
		args = append(args, *req.IPRangesURL)
		argNum++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *req.Enabled)
		argNum++
	}

	if len(sets) == 0 {
		return r.GetBySlug(ctx, slug)
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, slug)

	query := fmt.Sprintf(`
		UPDATE cloud_providers SET %s
		WHERE slug = $%d
		RETURNING id, name, slug, region, COALESCE(description, ''), ip_ranges,
		          COALESCE(ip_ranges_url, ''), last_updated, enabled, created_at, updated_at`,
		strings.Join(sets, ", "), argNum)

	var p model.CloudProvider
	var lastUpdated sql.NullTime
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&p.ID, &p.Name, &p.Slug, &p.Region, &p.Description,
		pq.Array(&p.IPRanges), &p.IPRangesURL, &lastUpdated,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update cloud provider: %w", err)
	}
	if lastUpdated.Valid {
		p.LastUpdated = &lastUpdated.Time
	}

	return &p, nil
}

// Delete deletes a cloud provider
func (r *CloudProviderRepository) Delete(ctx context.Context, slug string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM cloud_providers WHERE slug = $1", slug)
	return err
}

// GetIPRangesForProviders returns all IP ranges for given provider slugs
func (r *CloudProviderRepository) GetIPRangesForProviders(ctx context.Context, slugs []string) ([]string, error) {
	if len(slugs) == 0 {
		return []string{}, nil
	}

	query := `
		SELECT ip_ranges
		FROM cloud_providers
		WHERE slug = ANY($1) AND enabled = true`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(slugs))
	if err != nil {
		return nil, fmt.Errorf("failed to get IP ranges: %w", err)
	}
	defer rows.Close()

	var allRanges []string
	for rows.Next() {
		var ranges []string
		if err := rows.Scan(pq.Array(&ranges)); err != nil {
			return nil, fmt.Errorf("failed to scan IP ranges: %w", err)
		}
		allRanges = append(allRanges, ranges...)
	}

	return allRanges, nil
}

// UpdateIPRanges updates IP ranges and last_updated timestamp
func (r *CloudProviderRepository) UpdateIPRanges(ctx context.Context, slug string, ipRanges []string) error {
	query := `
		UPDATE cloud_providers
		SET ip_ranges = $1, last_updated = NOW(), updated_at = NOW()
		WHERE slug = $2`

	_, err := r.db.ExecContext(ctx, query, pq.Array(ipRanges), slug)
	return err
}

// UpdateIPRangesURL updates the IP ranges URL for a cloud provider
func (r *CloudProviderRepository) UpdateIPRangesURL(ctx context.Context, slug, url string) error {
	query := `
		UPDATE cloud_providers
		SET ip_ranges_url = $1, updated_at = NOW()
		WHERE slug = $2`

	_, err := r.db.ExecContext(ctx, query, url, slug)
	return err
}

// CloudProviderBlockingSettings holds blocked providers and challenge mode setting
type CloudProviderBlockingSettings struct {
	BlockedProviders []string `json:"blocked_providers"`
	ChallengeMode    bool     `json:"challenge_mode"`
	AllowSearchBots  bool     `json:"allow_search_bots"`
}

// GetBlockedCloudProviders returns blocked cloud provider slugs for a proxy host
func (r *CloudProviderRepository) GetBlockedCloudProviders(ctx context.Context, proxyHostID string) ([]string, error) {
	query := `
		SELECT COALESCE(blocked_cloud_providers, '{}')
		FROM geo_restrictions
		WHERE proxy_host_id = $1`

	var providers []string
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(pq.Array(&providers))
	if err == sql.ErrNoRows {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked cloud providers: %w", err)
	}

	return providers, nil
}

// GetCloudProviderBlockingSettings returns blocked providers and challenge mode for a proxy host
func (r *CloudProviderRepository) GetCloudProviderBlockingSettings(ctx context.Context, proxyHostID string) (*CloudProviderBlockingSettings, error) {
	query := `
		SELECT COALESCE(blocked_cloud_providers, '{}'), COALESCE(challenge_cloud_providers, false), COALESCE(allow_search_bots_cloud_providers, false)
		FROM geo_restrictions
		WHERE proxy_host_id = $1`

	var providers []string
	var challengeMode bool
	var allowSearchBots bool
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(pq.Array(&providers), &challengeMode, &allowSearchBots)
	if err == sql.ErrNoRows {
		return &CloudProviderBlockingSettings{
			BlockedProviders: []string{},
			ChallengeMode:    false,
			AllowSearchBots:  false,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cloud provider blocking settings: %w", err)
	}

	return &CloudProviderBlockingSettings{
		BlockedProviders: providers,
		ChallengeMode:    challengeMode,
		AllowSearchBots:  allowSearchBots,
	}, nil
}

// SetBlockedCloudProviders sets blocked cloud provider slugs for a proxy host
func (r *CloudProviderRepository) SetBlockedCloudProviders(ctx context.Context, proxyHostID string, slugs []string) error {
	// First check if geo_restriction exists for this proxy host
	var exists bool
	err := r.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM geo_restrictions WHERE proxy_host_id = $1)",
		proxyHostID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check geo_restriction: %w", err)
	}

	if exists {
		_, err = r.db.ExecContext(ctx,
			"UPDATE geo_restrictions SET blocked_cloud_providers = $1, updated_at = NOW() WHERE proxy_host_id = $2",
			pq.Array(slugs), proxyHostID,
		)
	} else {
		// Create a new geo_restriction with only blocked cloud providers
		_, err = r.db.ExecContext(ctx,
			`INSERT INTO geo_restrictions (proxy_host_id, mode, countries, enabled, blocked_cloud_providers)
			 VALUES ($1, 'blacklist', '{}', false, $2)`,
			proxyHostID, pq.Array(slugs),
		)
	}

	if err != nil {
		return fmt.Errorf("failed to set blocked cloud providers: %w", err)
	}

	return nil
}

// SetCloudProviderBlockingSettings sets blocked providers and challenge mode for a proxy host
func (r *CloudProviderRepository) SetCloudProviderBlockingSettings(ctx context.Context, proxyHostID string, settings *CloudProviderBlockingSettings) error {
	// First check if geo_restriction exists for this proxy host
	var exists bool
	err := r.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM geo_restrictions WHERE proxy_host_id = $1)",
		proxyHostID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check geo_restriction: %w", err)
	}

	if exists {
		_, err = r.db.ExecContext(ctx,
			`UPDATE geo_restrictions
			 SET blocked_cloud_providers = $1, challenge_cloud_providers = $2, allow_search_bots_cloud_providers = $3, updated_at = NOW()
			 WHERE proxy_host_id = $4`,
			pq.Array(settings.BlockedProviders), settings.ChallengeMode, settings.AllowSearchBots, proxyHostID,
		)
	} else {
		// Create a new geo_restriction with cloud provider settings
		_, err = r.db.ExecContext(ctx,
			`INSERT INTO geo_restrictions (proxy_host_id, mode, countries, enabled, blocked_cloud_providers, challenge_cloud_providers, allow_search_bots_cloud_providers)
			 VALUES ($1, 'blacklist', '{}', false, $2, $3, $4)`,
			proxyHostID, pq.Array(settings.BlockedProviders), settings.ChallengeMode, settings.AllowSearchBots,
		)
	}

	if err != nil {
		return fmt.Errorf("failed to set cloud provider blocking settings: %w", err)
	}

	return nil
}

// GetCloudProviderChallengeMode returns challenge mode setting for cloud provider blocking
func (r *CloudProviderRepository) GetCloudProviderChallengeMode(ctx context.Context, proxyHostID string) (bool, error) {
	query := `
		SELECT COALESCE(challenge_cloud_providers, false)
		FROM geo_restrictions
		WHERE proxy_host_id = $1`

	var challengeMode bool
	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(&challengeMode)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to get cloud provider challenge mode: %w", err)
	}

	return challengeMode, nil
}

// GetProxyHostIDsWithCloudProviderBlocking returns IDs of all proxy hosts with cloud provider blocking enabled
// If providerSlugs is provided, only returns hosts blocking any of those providers
// If providerSlugs is nil or empty, returns all hosts with any cloud provider blocking
func (r *CloudProviderRepository) GetProxyHostIDsWithCloudProviderBlocking(ctx context.Context, providerSlugs []string) ([]string, error) {
	var query string
	var args []interface{}

	if len(providerSlugs) == 0 {
		// Get all hosts with any cloud provider blocking
		query = `
			SELECT proxy_host_id
			FROM geo_restrictions
			WHERE blocked_cloud_providers IS NOT NULL
			  AND array_length(blocked_cloud_providers, 1) > 0`
	} else {
		// Get hosts blocking any of the specified providers
		query = `
			SELECT proxy_host_id
			FROM geo_restrictions
			WHERE blocked_cloud_providers IS NOT NULL
			  AND blocked_cloud_providers && $1`
		args = append(args, pq.Array(providerSlugs))
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy hosts with cloud provider blocking: %w", err)
	}
	defer rows.Close()

	var hostIDs []string
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return nil, fmt.Errorf("failed to scan proxy host ID: %w", err)
		}
		hostIDs = append(hostIDs, hostID)
	}

	return hostIDs, nil
}

// ExistsBySlug checks if a cloud provider with the given slug exists
func (r *CloudProviderRepository) ExistsBySlug(ctx context.Context, slug string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM cloud_providers WHERE slug = $1)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check cloud provider existence: %w", err)
	}
	return exists, nil
}

// CreateCloudProviderRequest for internal use (without strict validation)
type CreateCloudProviderRequest struct {
	Name        string
	Slug        string
	Region      string
	Description string
	IPRanges    []string
	IPRangesURL string
}

// CreateInternal creates a cloud provider (for internal use, allows empty IP ranges)
func (r *CloudProviderRepository) CreateInternal(ctx context.Context, req *CreateCloudProviderRequest) (*model.CloudProvider, error) {
	query := `
		INSERT INTO cloud_providers (name, slug, region, description, ip_ranges, ip_ranges_url)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, slug, region, description, ip_ranges, ip_ranges_url, last_updated, enabled, created_at, updated_at`

	var p model.CloudProvider
	var lastUpdated sql.NullTime
	var desc, url sql.NullString

	err := r.db.QueryRowContext(ctx, query,
		req.Name, req.Slug, req.Region, req.Description, pq.Array(req.IPRanges), req.IPRangesURL,
	).Scan(
		&p.ID, &p.Name, &p.Slug, &p.Region, &desc,
		pq.Array(&p.IPRanges), &url, &lastUpdated,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud provider: %w", err)
	}

	p.Description = desc.String
	p.IPRangesURL = url.String
	if lastUpdated.Valid {
		p.LastUpdated = &lastUpdated.Time
	}

	return &p, nil
}
