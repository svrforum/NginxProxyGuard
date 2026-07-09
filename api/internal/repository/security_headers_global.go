package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"nginx-proxy-guard/internal/model"
)

// GlobalSecurityHeadersRepository manages the singleton global_security_headers
// row — the global security-headers default hosts inherit unless they override
// or opt out (#198).
type GlobalSecurityHeadersRepository struct {
	db *sql.DB
}

func NewGlobalSecurityHeadersRepository(db *sql.DB) *GlobalSecurityHeadersRepository {
	return &GlobalSecurityHeadersRepository{db: db}
}

// GetGlobal returns the singleton global security-headers default, or a
// zero-value disabled default when no row exists.
func (r *GlobalSecurityHeadersRepository) GetGlobal(ctx context.Context) (*model.GlobalSecurityHeaders, error) {
	var g model.GlobalSecurityHeaders
	var csp, permPolicy sql.NullString
	var customHeaders []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT id, enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		       x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
		       content_security_policy, permissions_policy, custom_headers, created_at, updated_at
		FROM global_security_headers LIMIT 1
	`).Scan(&g.ID, &g.Enabled, &g.HSTSEnabled, &g.HSTSMaxAge, &g.HSTSIncludeSubdomains, &g.HSTSPreload,
		&g.XFrameOptions, &g.XContentTypeOptions, &g.XXSSProtection, &g.ReferrerPolicy,
		&csp, &permPolicy, &customHeaders, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return &model.GlobalSecurityHeaders{
			Enabled: false, HSTSEnabled: true, HSTSMaxAge: 31536000, HSTSIncludeSubdomains: true,
			XFrameOptions: "SAMEORIGIN", XContentTypeOptions: true, XXSSProtection: true,
			ReferrerPolicy: "strict-origin-when-cross-origin",
		}, nil
	}
	if err != nil {
		return nil, err
	}
	g.ContentSecurityPolicy = csp.String
	g.PermissionsPolicy = permPolicy.String
	if len(customHeaders) > 0 {
		json.Unmarshal(customHeaders, &g.CustomHeaders)
	}
	return &g, nil
}

// Upsert applies a partial update to the singleton, creating it if absent.
func (r *GlobalSecurityHeadersRepository) Upsert(ctx context.Context, req *model.UpdateGlobalSecurityHeadersRequest) (*model.GlobalSecurityHeaders, error) {
	cur, err := r.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	if req.HSTSEnabled != nil {
		cur.HSTSEnabled = *req.HSTSEnabled
	}
	if req.HSTSMaxAge > 0 {
		cur.HSTSMaxAge = req.HSTSMaxAge
	}
	if req.HSTSIncludeSubdomains != nil {
		cur.HSTSIncludeSubdomains = *req.HSTSIncludeSubdomains
	}
	if req.HSTSPreload != nil {
		cur.HSTSPreload = *req.HSTSPreload
	}
	if req.XFrameOptions != "" {
		cur.XFrameOptions = req.XFrameOptions
	}
	if req.XContentTypeOptions != nil {
		cur.XContentTypeOptions = *req.XContentTypeOptions
	}
	if req.XXSSProtection != nil {
		cur.XXSSProtection = *req.XXSSProtection
	}
	if req.ReferrerPolicy != "" {
		cur.ReferrerPolicy = req.ReferrerPolicy
	}
	// CSP / Permissions-Policy / custom headers are always taken from the
	// request (they can legitimately be cleared to empty).
	cur.ContentSecurityPolicy = req.ContentSecurityPolicy
	cur.PermissionsPolicy = req.PermissionsPolicy
	cur.CustomHeaders = req.CustomHeaders

	customHeadersJSON := []byte("{}")
	if len(cur.CustomHeaders) > 0 {
		customHeadersJSON, _ = json.Marshal(cur.CustomHeaders)
	}

	if cur.ID == "" {
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO global_security_headers (enabled, hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
			                                     x_frame_options, x_content_type_options, x_xss_protection, referrer_policy,
			                                     content_security_policy, permissions_policy, custom_headers)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`, cur.Enabled, cur.HSTSEnabled, cur.HSTSMaxAge, cur.HSTSIncludeSubdomains, cur.HSTSPreload,
			cur.XFrameOptions, cur.XContentTypeOptions, cur.XXSSProtection, cur.ReferrerPolicy,
			cur.ContentSecurityPolicy, cur.PermissionsPolicy, customHeadersJSON)
	} else {
		_, err = r.db.ExecContext(ctx, `
			UPDATE global_security_headers
			SET enabled=$1, hsts_enabled=$2, hsts_max_age=$3, hsts_include_subdomains=$4, hsts_preload=$5,
			    x_frame_options=$6, x_content_type_options=$7, x_xss_protection=$8, referrer_policy=$9,
			    content_security_policy=$10, permissions_policy=$11, custom_headers=$12, updated_at=NOW()
			WHERE id=$13
		`, cur.Enabled, cur.HSTSEnabled, cur.HSTSMaxAge, cur.HSTSIncludeSubdomains, cur.HSTSPreload,
			cur.XFrameOptions, cur.XContentTypeOptions, cur.XXSSProtection, cur.ReferrerPolicy,
			cur.ContentSecurityPolicy, cur.PermissionsPolicy, customHeadersJSON, cur.ID)
	}
	if err != nil {
		return nil, err
	}
	return r.GetGlobal(ctx)
}
