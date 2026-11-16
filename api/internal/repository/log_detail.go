package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"nginx-proxy-guard/internal/model"
)

// GetDetail reads the columns the list query leaves out, for one row. It
// returns nil when no row matches. created_at is the hypertable's time column:
// with it the lookup opens one chunk and, in a compressed one, only the
// batches whose created_at range holds the value.
func (r *LogRepository) GetDetail(ctx context.Context, id string, createdAt time.Time) (*model.LogDetail, error) {
	var protocol, referer, city, asn, ruleSeverity, attackType sql.NullString
	var serverPort sql.NullInt32
	err := r.db.QueryRowContext(ctx, `
		SELECT request_protocol, http_referer, geo_city, geo_asn, rule_severity, attack_type, server_port
		FROM logs_partitioned
		WHERE id = $1 AND created_at = $2
		LIMIT 1`, id, createdAt).Scan(&protocol, &referer, &city, &asn, &ruleSeverity, &attackType, &serverPort)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get log detail: %w", err)
	}

	d := &model.LogDetail{ID: id}
	for _, f := range []struct {
		src sql.NullString
		dst **string
	}{
		{protocol, &d.RequestProtocol},
		{referer, &d.HTTPReferer},
		{city, &d.GeoCity},
		{asn, &d.GeoASN},
		{ruleSeverity, &d.RuleSeverity},
		{attackType, &d.AttackType},
	} {
		if f.src.Valid {
			v := f.src.String
			*f.dst = &v
		}
	}
	if serverPort.Valid {
		port := int(serverPort.Int32)
		d.ServerPort = &port
	}
	return d, nil
}
