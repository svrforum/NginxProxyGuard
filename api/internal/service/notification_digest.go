package service

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
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

// Text renders the summary with no per-channel section. Callers that have a
// channel should use TextFor.
func (d *Digest) Text(lang, dashboardURL string) string {
	return d.text(lang, dashboardURL, nil)
}

// TextFor renders the summary for one channel, including the events that
// channel asked to hear about here rather than immediately.
//
// The body is otherwise shared: the counters, the blocked breakdown and the
// outstanding failures are properties of the install, not of the channel.
func (d *Digest) TextFor(lang, dashboardURL string, pending []repository.DigestPending) string {
	return d.text(lang, dashboardURL, pending)
}

// text renders the digest as plain text every channel can carry.
//
// The shape is deliberately uniform: an icon-led heading, then indented lines
// under it. A daily summary is skimmed on a phone, and a wall of unindented
// "label: value" pairs gives the eye nothing to land on.
func (d *Digest) text(lang, dashboardURL string, pending []repository.DigestPending) string {
	var b strings.Builder
	b.WriteString("📊 " + tr(lang, "digest.title") + "\n")

	// The dashboard's headline counters, so the summary answers "is everything
	// still standing" without opening a browser.
	if o := d.Overview; o != nil {
		b.WriteString("\n📋 " + tr(lang, "digest.overview"))
		fmt.Fprintf(&b, "\n  %s: %s", tr(lang, "digest.requests"), formatCount(o.RequestsTotal))
		fmt.Fprintf(&b, "\n  %s: %d / %d", tr(lang, "digest.hosts"), o.ProxyHostsEnabled, o.ProxyHostsTotal)
		if o.RedirectsEnabled > 0 {
			fmt.Fprintf(&b, "\n  %s: %d", tr(lang, "digest.redirects"), o.RedirectsEnabled)
		}
		fmt.Fprintf(&b, "\n  %s: %d", tr(lang, "digest.certificates"), o.CertificatesTotal)
		fmt.Fprintf(&b, "\n  %s: %d", tr(lang, "digest.bannedActive"), o.BannedIPsActive)
		b.WriteString("\n")
	}

	// What the machine itself is consuming. This sits with the headline
	// counters rather than at the end because storage is what actually kills a
	// home server: logs grow until the disk is full, and by then nginx cannot
	// write and Postgres cannot commit.
	if r := d.Resources; r != nil && (!r.RecordedAt.IsZero() || r.DatabaseBytes > 0) {
		b.WriteString("\n🖥 " + tr(lang, "digest.resources"))
		if !r.RecordedAt.IsZero() {
			fmt.Fprintf(&b, "\n  %s: %.0f%%", tr(lang, "digest.cpu"), r.CPUUsage)
			if r.MemoryTotal > 0 {
				fmt.Fprintf(&b, "\n  %s: %s / %s (%.0f%%)", tr(lang, "digest.memory"),
					formatBytes(r.MemoryUsed), formatBytes(r.MemoryTotal), r.MemoryUsage)
			}
			if r.DiskTotal > 0 {
				fmt.Fprintf(&b, "\n  %s: %s / %s (%.0f%%)", tr(lang, "digest.disk"),
					formatBytes(r.DiskUsed), formatBytes(r.DiskTotal), r.DiskUsage)
			}
		}
		if r.DatabaseBytes > 0 {
			fmt.Fprintf(&b, "\n  %s: %s", tr(lang, "digest.database"), formatBytes(r.DatabaseBytes))
		}
		if !r.RecordedAt.IsZero() && r.UptimeSeconds > 0 {
			fmt.Fprintf(&b, "\n  %s: %s", tr(lang, "digest.uptime"), formatUptime(lang, r.UptimeSeconds))
		}
		b.WriteString("\n")
	}

	if d.BlockedTotal == 0 {
		b.WriteString("\n✅ " + tr(lang, "digest.quiet"))
	} else {
		fmt.Fprintf(&b, "\n🛡 %s: %s", tr(lang, "digest.blocked"), formatCount(d.BlockedTotal))
		reasons := make([]string, 0, len(d.ByReason))
		for r := range d.ByReason {
			reasons = append(reasons, r)
		}
		sort.Slice(reasons, func(i, j int) bool { return d.ByReason[reasons[i]] > d.ByReason[reasons[j]] })
		for _, r := range reasons {
			fmt.Fprintf(&b, "\n  %s: %s", r, formatCount(d.ByReason[r]))
		}
	}

	// The events this channel chose to hear about here instead of immediately.
	// Counted rather than listed one by one: "요약에만" is what an operator
	// picks for the noisy ones, and reproducing every occurrence would undo the
	// reason they picked it.
	if len(pending) > 0 {
		b.WriteString("\n\n🔔 " + tr(lang, "digest.parked"))
		for _, p := range pending {
			line := "\n  " + eventTitle(lang, p.EventKey)
			if p.Count > 1 {
				line += fmt.Sprintf(" ×%d", p.Count)
			}
			if p.Subject != "" {
				line += " — " + p.Subject
			}
			b.WriteString(line)
		}
	}

	if len(d.TopBlockedIPs) > 0 {
		b.WriteString("\n\n🚫 " + tr(lang, "digest.topIPs"))
		for _, ip := range d.TopBlockedIPs {
			fmt.Fprintf(&b, "\n  %s — %s", ip.IP, formatCount(ip.Count))
		}
	}

	if len(d.ExpiringCerts) > 0 {
		b.WriteString("\n\n📜 " + tr(lang, "digest.certs"))
		for _, c := range d.ExpiringCerts {
			fmt.Fprintf(&b, "\n  %s", c)
		}
	}

	if len(d.Outstanding) > 0 {
		b.WriteString("\n\n⚠️ " + tr(lang, "digest.failing"))
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
		fmt.Fprintf(&b, "\n\n🔗 %s: %s", tr(lang, "digest.openDashboard"), strings.TrimRight(dashboardURL, "/"))
	}
	return b.String()
}

// pendingFor reads a channel's parked events, best-effort: a summary missing
// its held-back section is worth more than no summary at all.
func (s *NotificationDigestService) pendingFor(ctx context.Context, channelID string, now time.Time) []repository.DigestPending {
	if s.repo == nil {
		return nil
	}
	items, err := s.repo.PendingDigestItems(ctx, channelID, now.Add(-digestWindow))
	if err != nil {
		log.Printf("[Notify] failed to read parked digest items for channel %s: %v", channelID, err)
		return nil
	}
	return items
}

// formatCount groups thousands. 4556 and 4,556 carry the same information, but
// only one of them can be read at a glance on a phone.
func formatCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	if len(s) <= 3 {
		return sign + s
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return sign + b.String()
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
	// The preview reads the parked items but does NOT consume them: pressing
	// preview must not empty tomorrow's summary.
	pending := s.pendingFor(ctx, ch.ID, now)
	return model.RenderedMessage{
		Event:        "digest.daily",
		Severity:     "info",
		Preformatted: true,
		Text:         digest.TextFor(ch.Language, ch.DashboardURL, pending),
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
		// the same summary in different languages — and now also because the
		// parked events belong to the channel that asked for them.
		pending := s.pendingFor(ctx, ch.ID, now)
		text := digest.TextFor(ch.Language, ch.DashboardURL, pending)
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
		// Consumed only once the summary carrying them is queued, and bounded
		// by `now` so an event arriving during this loop lands in tomorrow's
		// rather than being marked delivered by a message that predates it.
		if len(pending) > 0 {
			if err := s.repo.ConsumeDigestItems(ctx, ch.ID, now); err != nil {
				log.Printf("[Notify] failed to consume parked items for channel %s: %v", ch.ID, err)
			}
		}
		sent++
	}
	return sent, nil
}
