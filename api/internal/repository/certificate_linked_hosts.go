package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
)

// Who is actually using this certificate.
//
// The panel used to answer that question client-side, by listing proxy hosts
// and grouping them by certificate_id. That was wrong twice over (#302):
//
//   - it asked for per_page=200, and the handler clamps anything above
//     MaxPerPage back to the DEFAULT of 20 rather than to the maximum — so on
//     any install with more than twenty hosts the grouping was built from an
//     arbitrary twenty of them, and certificates looked unused;
//   - redirect hosts reference certificates too and were never fetched at all,
//     so a certificate used only by a redirect always looked unused.
//
// Either one produces the same report: the row says nothing is linked, the
// delete comes back 409 "referenced by N host(s)", and the two cannot both be
// true. They were — the 409 counts both kinds, server-side, with no pagination
// in the way. So the count was right and the list was wrong.
//
// Answering it in one query beside the count removes the disagreement by
// construction. It also drops two client-side list fetches, so the certificates
// page no longer loads every proxy host just to render a column.
//
// UNION ALL, not two round-trips: the page needs both kinds interleaved per
// certificate, and this way "linked" has a single definition — the same one
// CountByCertificateID and the delete guard use.
//
// $1::uuid[] is explicit on purpose. certificate_id is a uuid column and
// there is no uuid = text operator, so a text[] cast does not merely perform
// worse — it fails outright. Leaving the parameter untyped happens to work,
// because Postgres infers the array type from the comparison, but stating it
// keeps the next reader from "fixing" it into ::text[].
const linkedHostsQuery = `
	SELECT certificate_id, kind, domains, enabled, target, cloudflare_proxied FROM (
		SELECT
			certificate_id,
			'proxy'::text AS kind,
			COALESCE(domain_names, '{}'::text[]) AS domains,
			enabled,
			-- An IPv6 literal needs brackets before the port (#314); one stored
			-- in brackets by an older version already has them.
			forward_scheme || '://'
				|| CASE WHEN strpos(forward_host, ':') > 0 AND left(forward_host, 1) <> '[' THEN '[' || forward_host || ']' ELSE forward_host END
				|| ':' || forward_port::text AS target,
			COALESCE(ddns_enabled, false) AND COALESCE(ddns_proxied, false) AS cloudflare_proxied
		FROM proxy_hosts
		WHERE certificate_id = ANY($1::uuid[])
		UNION ALL
		SELECT
			certificate_id,
			'redirect'::text AS kind,
			COALESCE(domain_names, '{}'::text[]) AS domains,
			enabled,
			-- Rendered the way the redirect hosts page renders it, so the two
			-- screens never disagree about where a host points: 'auto' means
			-- "follow the request scheme", which that page shows as https, and
			-- a configured path is part of the destination.
			CASE WHEN forward_scheme = 'auto' THEN 'https' ELSE forward_scheme END
				|| '://' || forward_domain_name || COALESCE(forward_path, '') AS target,
			false AS cloudflare_proxied
		FROM redirect_hosts
		WHERE certificate_id = ANY($1::uuid[])
	) linked
	ORDER BY domains[1]`

// ListLinkedHosts returns, per certificate id, the proxy and redirect hosts
// that reference it. Ids with no hosts are simply absent from the map; callers
// render that as "none".
//
// Takes the whole page's ids at once so the certificates list costs one extra
// query regardless of page size, rather than one per row.
func (r *CertificateRepository) ListLinkedHosts(ctx context.Context, certificateIDs []string) (map[string][]model.CertificateLinkedHost, error) {
	result := make(map[string][]model.CertificateLinkedHost)
	if len(certificateIDs) == 0 {
		return result, nil
	}

	rows, err := r.db.QueryContext(ctx, linkedHostsQuery, pq.Array(certificateIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts linked to certificates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		// certificate_id is nullable on both tables (the FKs are ON DELETE SET
		// NULL), and ANY($1) never matches NULL — but scanning into a string
		// would still be a latent panic if that ever changed, so take it as a
		// NullString and skip anything unset.
		var certID sql.NullString
		var domains pq.StringArray
		var host model.CertificateLinkedHost
		if err := rows.Scan(&certID, &host.Kind, &domains, &host.Enabled, &host.Target, &host.CloudflareProxied); err != nil {
			return nil, fmt.Errorf("failed to scan linked host: %w", err)
		}
		host.Domains = []string(domains)
		if !certID.Valid {
			continue
		}
		result[certID.String] = append(result[certID.String], host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read linked hosts: %w", err)
	}

	return result, nil
}
