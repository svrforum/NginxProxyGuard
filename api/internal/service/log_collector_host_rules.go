package service

import (
	"context"
	"log"
	"slices"
	"strconv"
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
)

// The hosts' log rules (#347): access log lines of a proxy host the
// collector does not store. They apply in handleAccessLine after fail2ban
// has counted the line, so a skipped line still counts towards a ban.

// hostLogRulesSource lists the log rules of every host that has some.
type hostLogRulesSource interface {
	ListActive(ctx context.Context) ([]model.HostLogRules, error)
}

// globalSettingsSource reads the global settings, for access_log_strip_query.
type globalSettingsSource interface {
	Get(ctx context.Context) (*model.GlobalSettings, error)
}

// hostLogRuleSet is the rules the collector applies: each host's filter, and
// whether path prefix rules can apply at all. They cannot while the access log
// strips the query string (#195): its request field is then nginx's $uri, with
// the spelling of the raw target, which decides a path rule, already gone.
type hostLogRuleSet struct {
	filters   map[string]*hostLogFilter
	pathRules bool
}

// hostLogFilter is a host's log rules compiled for the collector.
type hostLogFilter struct {
	all      bool
	statuses map[int]bool
	classes  [6]bool // classes[n] skips every nxx status
	methods  map[string]bool
	paths    []string
}

// compileHostLogFilter returns the filter of a host's rules, nil when they
// skip nothing.
func compileHostLogFilter(rules model.HostLogRules) *hostLogFilter {
	if rules.IsEmpty() {
		return nil
	}
	f := &hostLogFilter{all: rules.SkipAll, statuses: map[int]bool{}, methods: map[string]bool{}}
	for _, s := range rules.SkipStatuses {
		if class, ok := strings.CutSuffix(s, "xx"); ok {
			if n, err := strconv.Atoi(class); err == nil && n >= 1 && n <= 5 {
				f.classes[n] = true
			}
			continue
		}
		if code, err := strconv.Atoi(s); err == nil {
			f.statuses[code] = true
		}
	}
	for _, m := range rules.SkipMethods {
		f.methods[m] = true
	}
	f.paths = slices.Clone(rules.SkipPaths)
	return f
}

// skips reports whether the line is left out of the database. A nil filter
// skips nothing, and no filter skips a line NPG blocked (blockedByNPG). Path
// prefixes apply only with pathRules (hostLogRuleSet).
func (f *hostLogFilter) skips(r *model.CreateLogRequest, pathRules bool) bool {
	if f == nil || blockedByNPG(r) {
		return false
	}
	if f.all || f.statuses[r.StatusCode] || f.methods[r.RequestMethod] {
		return true
	}
	if class := r.StatusCode / 100; class >= 1 && class <= 5 && f.classes[class] {
		return true
	}
	if pathRules && len(f.paths) > 0 {
		// A path spelled so that nginx and the backend may read it
		// differently is never skipped (nginx.LogRulePath).
		if path, ok := nginx.LogRulePath(r.RequestURI); ok {
			for _, prefix := range f.paths {
				if strings.HasPrefix(path, prefix) {
					return true
				}
			}
		}
	}
	return false
}

// blockedByNPG reports whether NPG refused the request: the line has a block
// reason, or NPG answered it without asking the backend with an error status
// or a 302. A WAF block is the former kind without a reason; the 302 is the
// sign-in redirect of a ForwardAuth host, which carries none either. NPG's
// other redirect without the backend is the HTTPS one, a 301.
func blockedByNPG(r *model.CreateLogRequest) bool {
	if r.BlockReason != "" && r.BlockReason != model.BlockReasonNone {
		return true
	}
	return r.UpstreamAddr == "" && (r.StatusCode >= 400 || r.StatusCode == 302)
}

// SetLogRulesRepo wires the source of the hosts' log rules (#347), and the
// global settings, which say whether their path prefixes can apply.
func (c *LogCollector) SetLogRulesRepo(repo hostLogRulesSource, settings globalSettingsSource) {
	c.logRulesRepo = repo
	c.globalSettingsRepo = settings
}

// ReloadHostLogRules reads the hosts' log rules and the domain map again, so
// rules saved for a host apply from its next line, also on a host created
// since the last refresh (getHostIDByDomain).
func (c *LogCollector) ReloadHostLogRules(ctx context.Context) {
	c.refreshDomainCache(ctx)
	c.loadHostLogRules(ctx)
}

// loadHostLogRules replaces the hosts' log filters with the stored rules. A
// failed read keeps the filters it had, and is logged once until a read
// succeeds again. Path prefixes apply only once the global settings are read
// and the access log keeps the raw request target. Loads run one at a time, so
// a load that read before a save cannot replace what the save's load stored.
func (c *LogCollector) loadHostLogRules(ctx context.Context) {
	if c.logRulesRepo == nil {
		return
	}
	c.logRulesLoadMu.Lock()
	defer c.logRulesLoadMu.Unlock()
	rules, err := c.logRulesRepo.ListActive(ctx)
	if err != nil {
		if !c.logRulesLoadFailed.Swap(true) {
			log.Printf("[LogCollector] Could not read the hosts' log rules, so the ones read before still apply: %v", err)
		}
		return
	}
	c.logRulesLoadFailed.Store(false)
	set := &hostLogRuleSet{filters: make(map[string]*hostLogFilter, len(rules))}
	if prev := c.hostLogRules.Load(); prev != nil {
		set.pathRules = prev.pathRules
	}
	if c.globalSettingsRepo != nil {
		if gs, err := c.globalSettingsRepo.Get(ctx); err == nil && gs != nil {
			set.pathRules = !gs.AccessLogStripQuery
		}
	}
	for _, r := range rules {
		if f := compileHostLogFilter(r); f != nil {
			set.filters[r.ProxyHostID] = f
		}
	}
	c.hostLogRules.Store(set)
}

// skipsStorage reports whether the line's host leaves it out of the database.
func (c *LogCollector) skipsStorage(r *model.CreateLogRequest) bool {
	if r.ProxyHostID == "" {
		return false
	}
	set := c.hostLogRules.Load()
	if set == nil {
		return false
	}
	return set.filters[r.ProxyHostID].skips(r, set.pathRules)
}
