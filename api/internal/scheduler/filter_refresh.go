package scheduler

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// FilterRefreshScheduler handles periodic filter subscription refreshes
type FilterRefreshScheduler struct {
	service  *service.FilterSubscriptionService
	interval time.Duration
	stopChan chan struct{}
	running  bool
}

// NewFilterRefreshScheduler creates a new filter refresh scheduler
func NewFilterRefreshScheduler(svc *service.FilterSubscriptionService) *FilterRefreshScheduler {
	return &FilterRefreshScheduler{
		service:  svc,
		interval: config.FilterRefreshCheckInterval,
		stopChan: make(chan struct{}),
	}
}

// Start begins the filter refresh scheduler
func (s *FilterRefreshScheduler) Start() {
	if s.running {
		return
	}
	s.running = true

	go s.run()
	log.Printf("[Scheduler] Filter refresh scheduler started (check interval: %v)", s.interval)
}

// Stop stops the filter refresh scheduler
func (s *FilterRefreshScheduler) Stop() {
	if !s.running {
		return
	}
	close(s.stopChan)
	s.running = false
	log.Println("[Scheduler] Filter refresh scheduler stopped")
}

func (s *FilterRefreshScheduler) run() {
	// Initial delay before first check
	select {
	case <-time.After(30 * time.Second):
	case <-s.stopChan:
		return
	}

	// Run immediately after initial delay
	s.checkAndRefresh()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndRefresh()
		case <-s.stopChan:
			return
		}
	}
}

func (s *FilterRefreshScheduler) checkAndRefresh() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] Panic in filter refresh: %v", r)
		}
	}()

	ctx := context.Background()

	subs, err := s.service.GetEnabledSubscriptions(ctx)
	if err != nil {
		log.Printf("[Scheduler] Error getting enabled subscriptions: %v", err)
		return
	}

	if len(subs) == 0 {
		return
	}

	now := time.Now()
	refreshed := 0

	for _, sub := range subs {
		if s.isRefreshDue(sub, now) {
			log.Printf("[Scheduler] Refreshing filter subscription: %s (%s)", sub.Name, sub.ID)
			if _, err := s.service.Refresh(ctx, sub.ID); err != nil {
				log.Printf("[Scheduler] Failed to refresh subscription %s: %v", sub.ID, err)
			} else {
				refreshed++
			}
		}
	}

	if refreshed > 0 {
		log.Printf("[Scheduler] Refreshed %d filter subscription(s)", refreshed)
	}
}

// isRefreshDue checks if a subscription needs to be refreshed
func (s *FilterRefreshScheduler) isRefreshDue(sub model.FilterSubscription, now time.Time) bool {
	switch sub.RefreshType {
	case "interval":
		return s.isIntervalDue(sub, now)
	case "daily":
		return s.isDailyDue(sub, now)
	case "cron":
		return s.isCronDue(sub, now)
	default:
		return s.isIntervalDue(sub, now)
	}
}

// isIntervalDue checks if interval-based refresh is due
func (s *FilterRefreshScheduler) isIntervalDue(sub model.FilterSubscription, now time.Time) bool {
	if sub.LastFetchedAt == nil {
		return true
	}

	duration, err := time.ParseDuration(sub.RefreshValue)
	if err != nil {
		// Default to 24h if parse fails
		duration = 24 * time.Hour
	}

	return now.After(sub.LastFetchedAt.Add(duration))
}

// isDailyDue checks if daily refresh (HH:MM format) is due
func (s *FilterRefreshScheduler) isDailyDue(sub model.FilterSubscription, now time.Time) bool {
	parts := strings.Split(sub.RefreshValue, ":")
	if len(parts) != 2 {
		return false
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return false
	}

	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return false
	}

	// Target time for today
	target := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())

	// Check if target time has passed today
	if now.Before(target) {
		return false
	}

	// Check if already fetched today after the target time
	if sub.LastFetchedAt != nil {
		lastFetch := *sub.LastFetchedAt
		if lastFetch.Year() == now.Year() && lastFetch.Month() == now.Month() && lastFetch.Day() == now.Day() {
			if !lastFetch.Before(target) {
				return false
			}
		}
	}

	return true
}

// isCronDue checks if cron-based refresh is due (simple minute/hour cron)
func (s *FilterRefreshScheduler) isCronDue(sub model.FilterSubscription, now time.Time) bool {
	parts := strings.Fields(sub.RefreshValue)
	if len(parts) < 2 {
		return false
	}

	minuteSpec := parts[0]
	hourSpec := parts[1]

	if !matchCronField(minuteSpec, now.Minute()) {
		return false
	}
	if !matchCronField(hourSpec, now.Hour()) {
		return false
	}

	// Matched current time, check if already fetched in this minute
	if sub.LastFetchedAt != nil {
		lastFetch := *sub.LastFetchedAt
		if lastFetch.Year() == now.Year() && lastFetch.Month() == now.Month() &&
			lastFetch.Day() == now.Day() && lastFetch.Hour() == now.Hour() &&
			lastFetch.Minute() == now.Minute() {
			return false
		}
	}

	return true
}

// matchCronField matches a cron field spec against a value
func matchCronField(spec string, value int) bool {
	// Wildcard
	if spec == "*" {
		return true
	}

	// Step: */N
	if strings.HasPrefix(spec, "*/") {
		step, err := strconv.Atoi(spec[2:])
		if err != nil || step <= 0 {
			return false
		}
		return value%step == 0
	}

	// Exact value
	exact, err := strconv.Atoi(spec)
	if err != nil {
		return false
	}
	return value == exact
}

// CheckNow triggers an immediate refresh check
func (s *FilterRefreshScheduler) CheckNow() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Scheduler] Panic in immediate filter refresh: %v", r)
			}
		}()
		s.checkAndRefresh()
	}()
}

// FormatNextRefresh returns a human-readable next refresh time for a subscription
func FormatNextRefresh(sub model.FilterSubscription, now time.Time) string {
	switch sub.RefreshType {
	case "interval":
		if sub.LastFetchedAt == nil {
			return "pending"
		}
		duration, err := time.ParseDuration(sub.RefreshValue)
		if err != nil {
			return "unknown"
		}
		next := sub.LastFetchedAt.Add(duration)
		if now.After(next) {
			return "due"
		}
		return fmt.Sprintf("in %s", next.Sub(now).Truncate(time.Minute))
	case "daily":
		return fmt.Sprintf("daily at %s", sub.RefreshValue)
	case "cron":
		return fmt.Sprintf("cron: %s", sub.RefreshValue)
	default:
		return "unknown"
	}
}
