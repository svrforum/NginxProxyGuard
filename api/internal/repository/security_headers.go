package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"nginx-proxy-guard/internal/model"
)

type SecurityHeadersRepository struct {
	db *sql.DB
}

func NewSecurityHeadersRepository(db *sql.DB) *SecurityHeadersRepository {
	return &SecurityHeadersRepository{db: db}
}

func (r *SecurityHeadersRepository) GetByProxyHostID(ctx context.Context, proxyHostID string) (*model.SecurityHeaders, error) {
	query := `
		SELECT id, proxy_host_id, enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		       x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		       content_security_policy, permissions_policy, custom_headers, created_at, updated_at
		FROM security_headers
		WHERE proxy_host_id = $1
	`

	var sh model.SecurityHeaders
	var csp, permPolicy sql.NullString
	var customHeaders []byte

	err := r.db.QueryRowContext(ctx, query, proxyHostID).Scan(
		&sh.ID, &sh.ProxyHostID, &sh.Enabled, &sh.HSTSEnabled, &sh.HSTSMaxAge, &sh.HSTSIncludeSubdomains, &sh.HSTSPreload,
		&sh.XFrameOptions, &sh.XContentTypeOptions, &sh.XXSSProtection, &sh.ReferrerPolicy,
		&csp, &permPolicy, &customHeaders, &sh.CreatedAt, &sh.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	sh.ContentSecurityPolicy = csp.String
	sh.PermissionsPolicy = permPolicy.String

	if len(customHeaders) > 0 {
		json.Unmarshal(customHeaders, &sh.CustomHeaders)
	}

	return &sh, nil
}

func (r *SecurityHeadersRepository) Upsert(ctx context.Context, proxyHostID string, req *model.CreateSecurityHeadersRequest) (*model.SecurityHeaders, error) {
	customHeadersJSON := []byte("{}")
	if req.CustomHeaders != nil && len(req.CustomHeaders) > 0 {
		customHeadersJSON, _ = json.Marshal(req.CustomHeaders)
	}

	query := `
		INSERT INTO security_headers (proxy_host_id, enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		                              x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		                              content_security_policy, permissions_policy, custom_headers)
		VALUES ($1, COALESCE($2, TRUE), COALESCE($3, TRUE), COALESCE(NULLIF($4, 0), 31536000), COALESCE($5, TRUE), COALESCE($6, FALSE),
		        COALESCE(NULLIF($7, ''), 'SAMEORIGIN'), COALESCE($8, TRUE), COALESCE($9, TRUE),
		        COALESCE(NULLIF($10, ''), 'strict-origin-when-cross-origin'), $11, $12, $13)
		ON CONFLICT (proxy_host_id) DO UPDATE SET
			enabled = COALESCE($2, security_headers.enabled),
			hsts_enabled = COALESCE($3, security_headers.hsts_enabled),
			hsts_max_age = CASE WHEN $4 > 0 THEN $4 ELSE security_headers.hsts_max_age END,
			hsts_include_subdomains = COALESCE($5, security_headers.hsts_include_subdomains),
			hsts_preload = COALESCE($6, security_headers.hsts_preload),
			x_frame_options = CASE WHEN $7 != '' THEN $7 ELSE security_headers.x_frame_options END,
			x_content_type_options = COALESCE($8, security_headers.x_content_type_options),
			x_xss_protection = COALESCE($9, security_headers.x_xss_protection),
			referrer_policy = CASE WHEN $10 != '' THEN $10 ELSE security_headers.referrer_policy END,
			content_security_policy = $11,
			permissions_policy = $12,
			custom_headers = COALESCE($13, security_headers.custom_headers),
			updated_at = NOW()
		RETURNING id, proxy_host_id, enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		          x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		          content_security_policy, permissions_policy, custom_headers, created_at, updated_at
	`

	var sh model.SecurityHeaders
	var csp, permPolicy sql.NullString
	var customHeaders []byte

	err := r.db.QueryRowContext(ctx, query,
		proxyHostID, req.Enabled, req.HSTSEnabled, req.HSTSMaxAge, req.HSTSIncludeSubdomains, req.HSTSPreload,
		req.XFrameOptions, req.XContentTypeOptions, req.XXSSProtection, req.ReferrerPolicy,
		req.ContentSecurityPolicy,
		req.PermissionsPolicy,
		customHeadersJSON,
	).Scan(
		&sh.ID, &sh.ProxyHostID, &sh.Enabled, &sh.HSTSEnabled, &sh.HSTSMaxAge, &sh.HSTSIncludeSubdomains, &sh.HSTSPreload,
		&sh.XFrameOptions, &sh.XContentTypeOptions, &sh.XXSSProtection, &sh.ReferrerPolicy,
		&csp, &permPolicy, &customHeaders, &sh.CreatedAt, &sh.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	sh.ContentSecurityPolicy = csp.String
	sh.PermissionsPolicy = permPolicy.String

	if len(customHeaders) > 0 {
		json.Unmarshal(customHeaders, &sh.CustomHeaders)
	}

	return &sh, nil
}

func (r *SecurityHeadersRepository) Delete(ctx context.Context, proxyHostID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM security_headers WHERE proxy_host_id = $1", proxyHostID)
	return err
}

func (r *SecurityHeadersRepository) List(ctx context.Context) ([]model.SecurityHeaders, error) {
	query := `
		SELECT id, proxy_host_id, enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		       x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		       content_security_policy, permissions_policy, custom_headers, created_at, updated_at
		FROM security_headers
		WHERE enabled = TRUE
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var headers []model.SecurityHeaders
	for rows.Next() {
		var sh model.SecurityHeaders
		var csp, permPolicy sql.NullString
		var customHeaders []byte

		err := rows.Scan(
			&sh.ID, &sh.ProxyHostID, &sh.Enabled, &sh.HSTSEnabled, &sh.HSTSMaxAge, &sh.HSTSIncludeSubdomains, &sh.HSTSPreload,
			&sh.XFrameOptions, &sh.XContentTypeOptions, &sh.XXSSProtection, &sh.ReferrerPolicy,
			&csp, &permPolicy, &customHeaders, &sh.CreatedAt, &sh.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		sh.ContentSecurityPolicy = csp.String
		sh.PermissionsPolicy = permPolicy.String

		if len(customHeaders) > 0 {
			json.Unmarshal(customHeaders, &sh.CustomHeaders)
		}

		headers = append(headers, sh)
	}

	return headers, nil
}
