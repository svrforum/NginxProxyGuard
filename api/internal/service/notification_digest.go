package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// The daily digest (#221).
//
// What it contains was decided deliberately: aggregate counts, plus the
// addresses that were REFUSED. No visitor IP, path or user-agent appears,
// because the digest leaves the operator's network and a list of who visited
// would be exporting other people's browsing to Discord.
//
// The window is fixed at 24 hours. Anything wider crosses the 7-day compression
// boundary and costs far more; a weekly digest is a separate decision.

const (
	digestWindow      = 24 * time.Hour
	digestTopIPs      = 5
	certExpiryHorizon = 30 * 24 * time.Hour
	// resourceSampleMaxAge bounds how old a system_health row may be before the
	// digest stops quoting it. The collector writes every 30s, so anything this
	// stale means it is not running — and yesterday's CPU figure printed as if
	// it were current is worse than no figure at all.
	resourceSampleMaxAge = 15 * time.Minute
)

type digestSource interface {
	GetTopBlockedIPs(ctx context.Context, since time.Time, limit int) ([]model.IPStat, error)
	GetBlockBreakdown(ctx context.Context, since time.Time) (map[string]int64, int64, error)
	GetDigestOverview(ctx context.Context, since time.Time) (*repository.DigestOverview, error)
	GetDigestResources(ctx context.Context) (*repository.DigestResources, error)
}

type certExpirySource interface {
	GetExpiringSoon(ctx context.Context, days int) ([]model.Certificate, error)
}

type failureSource interface {
	OutstandingFailures(ctx context.Context) ([]model.NotificationState, error)
}

// NotificationDigestService builds the daily summary. It is pure query code and
// knows nothing about channels or HTTP.
type NotificationDigestService struct {
	dash  digestSource
	certs certExpirySource
	state failureSource
	repo  *repository.NotificationRepository
}

func NewNotificationDigestService(dash digestSource, certs certExpirySource, repo *repository.NotificationRepository) *NotificationDigestService {
	return &NotificationDigestService{dash: dash, certs: certs, state: repo, repo: repo}
}

// Digest is the assembled summary.
type Digest struct {
	Since         time.Time
	Overview      *repository.DigestOverview
	Resources     *repository.DigestResources
	BlockedTotal  int64
	ByReason      map[string]int64
	TopBlockedIPs []model.IPStat
	ExpiringCerts []string
	Outstanding   []model.NotificationState
}

// Build assembles the previous 24 hours.
func (s *NotificationDigestService) Build(ctx context.Context, now time.Time) (*Digest, error) {
	since := now.Add(-digestWindow)
	d := &Digest{Since: since, ByReason: map[string]int64{}}

	if s.dash != nil {
		if ov, err := s.dash.GetDigestOverview(ctx, since); err == nil {
			d.Overview = ov
		}

		// Best-effort, like the overview above and unlike the breakdown below:
		// a resource read that fails must cost the digest its resource lines,
		// not cost every channel its whole summary for that hour.
		if res, err := s.dash.GetDigestResources(ctx); err == nil && res != nil {
			if !res.RecordedAt.IsZero() && now.Sub(res.RecordedAt) > resourceSampleMaxAge {
				res.RecordedAt = time.Time{} // stale sample: keep storage, drop the host lines
			}
			d.Resources = res
		}

		byReason, total, err := s.dash.GetBlockBreakdown(ctx, since)
		if err != nil {
			return nil, err
		}
		d.ByReason, d.BlockedTotal = byReason, total

		ips, err := s.dash.GetTopBlockedIPs(ctx, since, digestTopIPs)
		if err != nil {
			return nil, err
		}
		d.TopBlockedIPs = ips
	}

	if s.certs != nil {
		certs, err := s.certs.GetExpiringSoon(ctx, int(certExpiryHorizon/(24*time.Hour)))
		if err == nil {
			for _, c := range certs {
				name := strings.Join(c.DomainNames, ", ")
				if c.ExpiresAt != nil {
					days := int(time.Until(*c.ExpiresAt).Hours() / 24)
					name = fmt.Sprintf("%s (%dd)", name, days)
				}
				d.ExpiringCerts = append(d.ExpiringCerts, name)
			}
		}
	}

	// Anything still broken. This is where a long-running failure keeps
	// appearing after its single edge-triggered alert, which is the other half
	// of the bargain edge triggering makes.
	if s.state != nil {
		if failures, err := s.state.OutstandingFailures(ctx); err == nil {
			d.Outstanding = failures
		}
	}
	return d, nil
}

// Text renders the digest as plain text every channel can carry.
func (d *Digest) Text(lang, dashboardURL string) string {
	var b strings.Builder
	b.WriteString(tr(lang, "digest.title") + "\n")

	// The dashboard's headline counters, so the summary answers "is everything
	// still standing" without opening a browser.
	if o := d.Overview; o != nil {
		fmt.Fprintf(&b, "\n%s: %d", tr(lang, "digest.requests"), o.RequestsTotal)
		fmt.Fprintf(&b, "\n%s: %d / %d", tr(lang, "digest.hosts"), o.ProxyHostsEnabled, o.ProxyHostsTotal)
		if o.RedirectsEnabled > 0 {
			fmt.Fprintf(&b, "\n%s: %d", tr(lang, "digest.redirects"), o.RedirectsEnabled)
		}
		fmt.Fprintf(&b, "\n%s: %d", tr(lang, "digest.certificates"), o.CertificatesTotal)
		fmt.Fprintf(&b, "\n%s: %d", tr(lang, "digest.bannedActive"), o.BannedIPsActive)
		b.WriteString("\n")
	}

	// What the machine itself is consuming. This sits with the headline
	// counters rather than at the end because storage is what actually kills a
	// home server: logs grow until the disk is full, and by then nginx cannot
	// write and Postgres cannot commit.
	if r := d.Resources; r != nil && (!r.RecordedAt.IsZero() || r.DatabaseBytes > 0) {
		if !r.RecordedAt.IsZero() {
			fmt.Fprintf(&b, "\n%s: %.0f%%", tr(lang, "digest.cpu"), r.CPUUsage)
			if r.MemoryTotal > 0 {
				fmt.Fprintf(&b, "\n%s: %s / %s (%.0f%%)", tr(lang, "digest.memory"),
					formatBytes(r.MemoryUsed), formatBytes(r.MemoryTotal), r.MemoryUsage)
			}
			if r.DiskTotal > 0 {
				fmt.Fprintf(&b, "\n%s: %s / %s (%.0f%%)", tr(lang, "digest.disk"),
					formatBytes(r.DiskUsed), formatBytes(r.DiskTotal), r.DiskUsage)
			}
		}
		if r.DatabaseBytes > 0 {
			fmt.Fprintf(&b, "\n%s: %s", tr(lang, "digest.database"), formatBytes(r.DatabaseBytes))
		}
		if !r.RecordedAt.IsZero() && r.UptimeSeconds > 0 {
			fmt.Fprintf(&b, "\n%s: %s", tr(lang, "digest.uptime"), formatUptime(lang, r.UptimeSeconds))
		}
		b.WriteString("\n")
	}

	if d.BlockedTotal == 0 {
		b.WriteString("\n" + tr(lang, "digest.quiet"))
	} else {
		fmt.Fprintf(&b, "\n%s: %d", tr(lang, "digest.blocked"), d.BlockedTotal)
		reasons := make([]string, 0, len(d.ByReason))
		for r := range d.ByReason {
			reasons = append(reasons, r)
		}
		sort.Slice(reasons, func(i, j int) bool { return d.ByReason[reasons[i]] > d.ByReason[reasons[j]] })
		for _, r := range reasons {
			fmt.Fprintf(&b, "\n  %s: %d", r, d.ByReason[r])
		}
	}

	if len(d.TopBlockedIPs) > 0 {
		b.WriteString("\n\n" + tr(lang, "digest.topIPs") + ":")
		for _, ip := range d.TopBlockedIPs {
			fmt.Fprintf(&b, "\n  %s — %d", ip.IP, ip.Count)
		}
	}

	if len(d.ExpiringCerts) > 0 {
		b.WriteString("\n\n" + tr(lang, "digest.certs") + ":")
		for _, c := range d.ExpiringCerts {
			fmt.Fprintf(&b, "\n  %s", c)
		}
	}

	if len(d.Outstanding) > 0 {
		b.WriteString("\n\n" + tr(lang, "digest.failing") + ":")
		for _, f := range d.Outstanding {
			// Label over Subject: the subject is a UUID, and a summary that
			// names the broken thing by its database id tells the reader
			// nothing. Rows written before labels existed still fall back.
			name := f.Label
			if name == "" {
				name = f.Subject
			}
			fmt.Fprintf(&b, "\n  %s — %s (%s %s)", eventTitle(lang, f.EventKey), name, tr(lang, "digest.since"), f.Since.Format("2006-01-02 15:04"))
		}
	}

	// The numbers answer "what happened"; the link is how you get to the graphs
	// without hunting for the address. Omitted entirely when unset rather than
	// printing a dangling label.
	if dashboardURL != "" {
		fmt.Fprintf(&b, "\n\n%s: %s", tr(lang, "digest.openDashboard"), strings.TrimRight(dashboardURL, "/"))
	}
	return b.String()
}

// Byte counts reuse formatBytes from docker_stats.go — the same formatting the
// container cards already show, so a size in the summary reads identically to
// the same size in the UI.

// formatUptime renders a duration in the channel's language, coarsest unit
// first. An operator reads this for one thing — whether the box rebooted — so
// two units is enough and seconds never appear.
func formatUptime(lang string, seconds int64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d%s %d%s", days, tr(lang, "unit.day"), hours, tr(lang, "unit.hour"))
	case hours > 0:
		return fmt.Sprintf("%d%s %d%s", hours, tr(lang, "unit.hour"), minutes, tr(lang, "unit.minute"))
	default:
		return fmt.Sprintf("%d%s", minutes, tr(lang, "unit.minute"))
	}
}

// BuildPreview renders the digest a channel would receive right now, from real
// data. It backs the preview button: waiting until the configured hour to find
// out whether the summary is useful is not a workable feedback loop.
func (s *NotificationDigestService) BuildPreview(ctx context.Context, ch *model.NotificationChannel, now time.Time) (model.RenderedMessage, error) {
	digest, err := s.Build(ctx, now)
	if err != nil {
		return model.RenderedMessage{}, err
	}
	return model.RenderedMessage{
		Event:        "digest.daily",
		Severity:     "info",
		Preformatted: true,
		Text:         digest.Text(ch.Language, ch.DashboardURL),
		Fields: map[string]string{
			"event": "digest.daily",
			"time":  now.Format(time.RFC3339),
			"count": fmt.Sprintf("%d", digest.BlockedTotal),
		},
		At: now,
	}, nil
}

// SendDue queues a digest for every channel whose hour has come and which has
// not already had one today.
func (s *NotificationDigestService) SendDue(ctx context.Context, now time.Time) (int, error) {
	if s.repo == nil || !s.repo.TablesExist(ctx) {
		return 0, nil
	}
	channels, err := s.repo.ChannelsForDigest(ctx, now.Hour(), now)
	if err != nil {
		return 0, err
	}
	if len(channels) == 0 {
		return 0, nil
	}

	digest, err := s.Build(ctx, now)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, ch := range channels {
		// Rendered per channel, not once: two channels can legitimately want
		// the same summary in different languages.
		text := digest.Text(ch.Language, ch.DashboardURL)
		msg := model.RenderedMessage{
			Event:    "digest.daily",
			Severity: "info",
			// The digest composes its whole body; the formatter must pass it
			// through rather than rebuild it from headline and fields.
			Preformatted: true,
			Text:         text,
			Fields: map[string]string{
				"event": "digest.daily",
				"time":  now.Format(time.RFC3339),
				"count": fmt.Sprintf("%d", digest.BlockedTotal),
			},
			At: now,
		}
		if err := s.repo.Enqueue(ctx, ch.ID, "digest.daily", msg); err != nil {
			return sent, err
		}
		// Marked before delivery on purpose: the scheduler ticks hourly and a
		// retried tick must not produce a second digest. A digest that fails to
		// send is visible in the delivery log, which is the right place for it.
		if err := s.repo.MarkDigestSent(ctx, ch.ID, now); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}
