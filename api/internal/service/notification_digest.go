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
)

type digestSource interface {
	GetTopBlockedIPs(ctx context.Context, since time.Time, limit int) ([]model.IPStat, error)
	GetBlockBreakdown(ctx context.Context, since time.Time) (map[string]int64, int64, error)
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
func (d *Digest) Text() string {
	var b strings.Builder
	b.WriteString("Nginx Proxy Guard — last 24 hours\n")

	if d.BlockedTotal == 0 {
		b.WriteString("\nNothing was blocked.")
	} else {
		fmt.Fprintf(&b, "\nBlocked requests: %d", d.BlockedTotal)
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
		b.WriteString("\n\nMost blocked addresses:")
		for _, ip := range d.TopBlockedIPs {
			fmt.Fprintf(&b, "\n  %s — %d", ip.IP, ip.Count)
		}
	}

	if len(d.ExpiringCerts) > 0 {
		b.WriteString("\n\nCertificates expiring within 30 days:")
		for _, c := range d.ExpiringCerts {
			fmt.Fprintf(&b, "\n  %s", c)
		}
	}

	if len(d.Outstanding) > 0 {
		b.WriteString("\n\nStill failing:")
		for _, f := range d.Outstanding {
			fmt.Fprintf(&b, "\n  %s — %s (since %s)", f.EventKey, f.Subject, f.Since.Format("2006-01-02 15:04"))
		}
	}
	return b.String()
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
	text := digest.Text()

	sent := 0
	for _, ch := range channels {
		msg := model.RenderedMessage{
			Event:    "digest.daily",
			Severity: "info",
			Text:     text,
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
