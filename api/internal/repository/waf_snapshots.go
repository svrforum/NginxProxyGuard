package repository

import (
	"context"
	"database/sql"
	"fmt"

	"nginx-proxy-guard/internal/model"
)

// ============================================================================
// WAF Rule Snapshots (Versioning)
// ============================================================================

func (r *WAFRepository) CreateSnapshot(ctx context.Context, snapshot *model.WAFRuleSnapshot) (*model.WAFRuleSnapshot, error) {
	// Get next version number
	var nextVersion int
	versionQuery := `
		SELECT COALESCE(MAX(version_number), 0) + 1
		FROM waf_rule_snapshots
		WHERE ($1::uuid IS NULL AND proxy_host_id IS NULL) OR proxy_host_id = $1
	`
	err := r.db.QueryRowContext(ctx, versionQuery, snapshot.ProxyHostID).Scan(&nextVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get next version number: %w", err)
	}

	query := `
		INSERT INTO waf_rule_snapshots (
			proxy_host_id, version_number, snapshot_name, rule_engine, paranoia_level,
			anomaly_threshold, total_rules, disabled_rules, change_description, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at
	`

	err = r.db.QueryRowContext(ctx, query,
		snapshot.ProxyHostID,
		nextVersion,
		snapshot.SnapshotName,
		snapshot.RuleEngine,
		snapshot.ParanoiaLevel,
		snapshot.AnomalyThreshold,
		snapshot.TotalRules,
		snapshot.DisabledRules,
		snapshot.ChangeDescription,
		snapshot.CreatedBy,
	).Scan(&snapshot.ID, &snapshot.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create WAF snapshot: %w", err)
	}

	snapshot.VersionNumber = nextVersion
	return snapshot, nil
}

// CreateSnapshotDetail creates a snapshot detail record for a rule
func (r *WAFRepository) CreateSnapshotDetail(ctx context.Context, detail *model.WAFRuleSnapshotDetail) error {
	query := `
		INSERT INTO waf_rule_snapshot_details (
			snapshot_id, rule_id, rule_category, rule_description, is_disabled, reason
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`

	return r.db.QueryRowContext(ctx, query,
		detail.SnapshotID,
		detail.RuleID,
		detail.RuleCategory,
		detail.RuleDescription,
		detail.IsDisabled,
		detail.Reason,
	).Scan(&detail.ID)
}

// GetSnapshotByID retrieves a snapshot by ID with its details
func (r *WAFRepository) GetSnapshotByID(ctx context.Context, id string) (*model.WAFRuleSnapshot, error) {
	query := `
		SELECT id, proxy_host_id, version_number, snapshot_name, rule_engine, paranoia_level,
			anomaly_threshold, total_rules, disabled_rules, change_description, created_by, created_at
		FROM waf_rule_snapshots
		WHERE id = $1
	`

	var snapshot model.WAFRuleSnapshot
	var proxyHostID sql.NullString
	var snapshotName, ruleEngine, changeDesc, createdBy sql.NullString
	var paranoiaLevel, anomalyThreshold sql.NullInt32

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&snapshot.ID,
		&proxyHostID,
		&snapshot.VersionNumber,
		&snapshotName,
		&ruleEngine,
		&paranoiaLevel,
		&anomalyThreshold,
		&snapshot.TotalRules,
		&snapshot.DisabledRules,
		&changeDesc,
		&createdBy,
		&snapshot.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get WAF snapshot: %w", err)
	}

	if proxyHostID.Valid {
		snapshot.ProxyHostID = &proxyHostID.String
	}
	if snapshotName.Valid {
		snapshot.SnapshotName = snapshotName.String
	}
	if ruleEngine.Valid {
		snapshot.RuleEngine = ruleEngine.String
	}
	if paranoiaLevel.Valid {
		snapshot.ParanoiaLevel = int(paranoiaLevel.Int32)
	}
	if anomalyThreshold.Valid {
		snapshot.AnomalyThreshold = int(anomalyThreshold.Int32)
	}
	if changeDesc.Valid {
		snapshot.ChangeDescription = changeDesc.String
	}
	if createdBy.Valid {
		snapshot.CreatedBy = createdBy.String
	}

	return &snapshot, nil
}

// ListSnapshots returns snapshots for a proxy host (or global if proxyHostID is nil)
func (r *WAFRepository) ListSnapshots(ctx context.Context, proxyHostID *string, limit int) ([]model.WAFRuleSnapshot, error) {
	query := `
		SELECT id, proxy_host_id, version_number, snapshot_name, rule_engine, paranoia_level,
			anomaly_threshold, total_rules, disabled_rules, change_description, created_by, created_at
		FROM waf_rule_snapshots
		WHERE ($1::uuid IS NULL AND proxy_host_id IS NULL) OR proxy_host_id = $1
		ORDER BY version_number DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, proxyHostID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list WAF snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []model.WAFRuleSnapshot
	for rows.Next() {
		var snapshot model.WAFRuleSnapshot
		var hostID sql.NullString
		var snapshotName, ruleEngine, changeDesc, createdBy sql.NullString
		var paranoiaLevel, anomalyThreshold sql.NullInt32

		err := rows.Scan(
			&snapshot.ID,
			&hostID,
			&snapshot.VersionNumber,
			&snapshotName,
			&ruleEngine,
			&paranoiaLevel,
			&anomalyThreshold,
			&snapshot.TotalRules,
			&snapshot.DisabledRules,
			&changeDesc,
			&createdBy,
			&snapshot.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan WAF snapshot: %w", err)
		}

		if hostID.Valid {
			snapshot.ProxyHostID = &hostID.String
		}
		if snapshotName.Valid {
			snapshot.SnapshotName = snapshotName.String
		}
		if ruleEngine.Valid {
			snapshot.RuleEngine = ruleEngine.String
		}
		if paranoiaLevel.Valid {
			snapshot.ParanoiaLevel = int(paranoiaLevel.Int32)
		}
		if anomalyThreshold.Valid {
			snapshot.AnomalyThreshold = int(anomalyThreshold.Int32)
		}
		if changeDesc.Valid {
			snapshot.ChangeDescription = changeDesc.String
		}
		if createdBy.Valid {
			snapshot.CreatedBy = createdBy.String
		}

		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

// ============================================================================
// WAF Rule Change Events
// ============================================================================

// RecordRuleChangeEvent records a rule enable/disable event
func (r *WAFRepository) RecordRuleChangeEvent(ctx context.Context, event *model.WAFRuleChangeEvent) error {
	query := `
		INSERT INTO waf_rule_change_events (
			proxy_host_id, rule_id, action, rule_category, rule_description, reason, changed_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`

	return r.db.QueryRowContext(ctx, query,
		event.ProxyHostID,
		event.RuleID,
		event.Action,
		event.RuleCategory,
		event.RuleDescription,
		event.Reason,
		event.ChangedBy,
	).Scan(&event.ID, &event.CreatedAt)
}

// GetRuleChangeEvents returns change events for a proxy host
func (r *WAFRepository) GetRuleChangeEvents(ctx context.Context, proxyHostID *string, limit int) ([]model.WAFRuleChangeEvent, error) {
	query := `
		SELECT id, proxy_host_id, rule_id, action, rule_category, rule_description, reason, changed_by, created_at
		FROM waf_rule_change_events
		WHERE ($1::uuid IS NULL AND proxy_host_id IS NULL) OR proxy_host_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, proxyHostID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get WAF rule change events: %w", err)
	}
	defer rows.Close()

	var events []model.WAFRuleChangeEvent
	for rows.Next() {
		var event model.WAFRuleChangeEvent
		var hostID, ruleCategory, ruleDescription, reason, changedBy sql.NullString

		err := rows.Scan(
			&event.ID,
			&hostID,
			&event.RuleID,
			&event.Action,
			&ruleCategory,
			&ruleDescription,
			&reason,
			&changedBy,
			&event.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan WAF rule change event: %w", err)
		}

		if hostID.Valid {
			event.ProxyHostID = &hostID.String
		}
		if ruleCategory.Valid {
			event.RuleCategory = ruleCategory.String
		}
		if ruleDescription.Valid {
			event.RuleDescription = ruleDescription.String
		}
		if reason.Valid {
			event.Reason = reason.String
		}
		if changedBy.Valid {
			event.ChangedBy = changedBy.String
		}

		events = append(events, event)
	}

	return events, nil
}
