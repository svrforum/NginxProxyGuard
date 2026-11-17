package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// accessListStore is what the handler needs of repository.AccessListRepository.
type accessListStore interface {
	List(ctx context.Context, page, perPage int) ([]model.AccessList, int, error)
	GetByID(ctx context.Context, id string) (*model.AccessList, error)
	Create(ctx context.Context, req *model.CreateAccessListRequest) (*model.AccessList, error)
	Update(ctx context.Context, id string, req *model.UpdateAccessListRequest) (*model.AccessList, error)
	Delete(ctx context.Context, id string) error
}

// accessListHosts is what the handler needs of service.ProxyHostService: the
// hosts that render a list.
type accessListHosts interface {
	RegenerateConfigsForAccessList(ctx context.Context, accessListID string) error
	GetHostIDsByAccessList(ctx context.Context, accessListID string) ([]string, error)
	RegenerateConfigsForHostIDs(ctx context.Context, hostIDs []string) error
	// Basic auth accounts (#387): a host with ForwardAuth refuses them, and a
	// deleted list's htpasswd file is removed.
	AccessListUsedWithAuthProvider(ctx context.Context, listID string) (string, error)
	RemoveAccessListHtpasswd(listID string)
}

// accessListAuditor is what the handler records (service.AuditService).
type accessListAuditor interface {
	LogAccessListCreated(ctx context.Context, name string) error
	LogAccessListUpdated(ctx context.Context, name string, details map[string]interface{}) error
	LogAccessListDeleted(ctx context.Context, name string) error
	LogDNSEntryConfirmed(ctx context.Context, name string, addrs []string, canonical string, scopes []string) error
}

// accessListDNS is what the handler needs of service.DNSEntryService (#320).
type accessListDNS interface {
	ValidateScopeNames(ctx context.Context, scope string, names []string) error
	SyncScope(ctx context.Context, scope string, names []string) error
	Statuses(ctx context.Context, names []string, view model.DNSStatusView) (map[string]model.DNSEntryStatus, error)
	LoginBypassHosts(listID string) []model.DNSHostRef
	References(ctx context.Context, name string) ([]model.DNSReference, error)
	Confirm(ctx context.Context, name string, expected []string, expectedCanonical string) (model.DNSEntryStatus, nginx.DNSApplyResult, error)
}

// AccessListHandler serves /access-lists. Its dependencies sit behind the
// narrow interfaces above, so its tests can use fakes.
type AccessListHandler struct {
	repo       accessListStore
	proxyHosts accessListHosts
	audit      accessListAuditor
	// dns is the DNS entry service (SetDNSEntries). Without it a list's
	// domains are stored but get no state here, and nothing writes the
	// include files that hold their addresses, so they let no one in.
	dns accessListDNS
}

func NewAccessListHandler(repo *repository.AccessListRepository, proxyHosts *service.ProxyHostService, audit *service.AuditService) *AccessListHandler {
	return &AccessListHandler{repo: repo, proxyHosts: proxyHosts, audit: audit}
}

// SetDNSEntries wires the DNS entry service (#320): a save hands the list's
// domains to it, the responses carry their state, and ConfirmDNS goes
// through it.
func (h *AccessListHandler) SetDNSEntries(svc *service.DNSEntryService) {
	if svc != nil {
		h.dns = svc
	}
}

// List returns a paginated list of access lists.
// Query parameters: page (default: 1), per_page (default: 20, max: 100)
func (h *AccessListHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)

	lists, total, err := h.repo.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list access lists", err)
	}

	return c.JSON(http.StatusOK, accessListListResponse{
		AccessListListResponse: model.AccessListListResponse{
			Total:      total,
			Page:       page,
			PerPage:    perPage,
			TotalPages: CalculateTotalPages(total, perPage),
		},
		Data: h.viewsOf(c, lists),
	})
}

// Create creates a new access list.
func (h *AccessListHandler) Create(c echo.Context) error {
	ctx := c.Request().Context()
	var req model.CreateAccessListRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	// Validate required fields
	if err := ValidateRequired(req.Name, "name"); err != nil {
		return validationError(c, "name", "is required")
	}

	// Validate field lengths
	if err := ValidateStringLength(req.Name, MaxNameLength, "name"); err != nil {
		return validationError(c, "name", err.(*ValidationError).Message)
	}

	// The rules become allow/deny lines in each host's config, and the
	// name and rule descriptions comments beside them.
	if err := model.ValidateCreateAccessListRequest(&req); err != nil {
		return accessListRulesRefused(c, err)
	}
	if err := hashAccessListAuthUsers(req.AuthUsers); err != nil {
		return internalError(c, "hash access list passwords", err)
	}
	// The list has no id yet: a scope no list owns stands for it.
	names := requestDNSNames(req.Items)
	if err := h.checkDNSLimits(ctx, model.AccessListDNSScope(uuid.NewString()), names); err != nil {
		return accessListRulesRefused(c, err)
	}

	list, err := h.repo.Create(ctx, &req)
	if err != nil {
		return databaseError(c, "create access list", err)
	}

	h.audit.LogAccessListCreated(service.ContextWithAudit(ctx, c), list.Name)
	h.syncDNSNames(ctx, list, nil, names)
	return createdResponse(c, h.viewOf(c, list))
}

// Get retrieves an access list by ID.
func (h *AccessListHandler) Get(c echo.Context) error {
	id := c.Param("id")
	list, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}
	return c.JSON(http.StatusOK, h.viewOf(c, list))
}

// Update updates an existing access list.
func (h *AccessListHandler) Update(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()
	var req model.UpdateAccessListRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	// Validate field lengths if name is provided
	if req.Name != nil && *req.Name != "" {
		if err := ValidateStringLength(*req.Name, MaxNameLength, "name"); err != nil {
			return validationError(c, "name", err.(*ValidationError).Message)
		}
	}

	// The stored rules are read first: a rule sent back as it was read
	// keeps what it is (model.ValidateUpdateAccessListRequest).
	before, err := h.repo.GetByID(ctx, id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if before == nil {
		return notFoundError(c, "Access list")
	}
	if err := model.ValidateUpdateAccessListRequest(&req, before.Items); err != nil {
		return accessListRulesRefused(c, err)
	}
	if req.AuthUsers != nil {
		if err := model.ValidateAccessListAuthUsers(req.AuthUsers, before.AuthUsers); err != nil {
			return accessListRulesRefused(c, err)
		}
		// ForwardAuth answers a missing login with 401 too and would take the
		// password prompt over (#387).
		if len(req.AuthUsers) > 0 {
			host, err := h.proxyHosts.AccessListUsedWithAuthProvider(ctx, id)
			if err != nil {
				return databaseError(c, "list access list dependents", err)
			}
			if host != "" {
				return conflictError(c, "proxy host "+host+" uses this access list with an auth provider (ForwardAuth), which cannot be combined with a username and password; remove one of them first")
			}
		}
		if err := hashAccessListAuthUsers(req.AuthUsers); err != nil {
			return internalError(c, "hash access list passwords", err)
		}
	}
	beforeNames := accessListDNSNames(before.Items)
	afterNames := beforeNames
	if req.Items != nil {
		afterNames = requestDNSNames(req.Items)
		if err := h.checkDNSLimits(ctx, model.AccessListDNSScope(before.ID), afterNames); err != nil {
			return accessListRulesRefused(c, err)
		}
	}

	list, err := h.repo.Update(ctx, id, &req)
	if err != nil {
		return databaseError(c, "update access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}
	post, cancel := afterAccessListCommit(ctx)
	defer cancel()
	// Recorded before the nginx regeneration: the change is saved even if
	// applying it to nginx fails below.
	h.audit.LogAccessListUpdated(service.ContextWithAudit(post, c), list.Name, accessListChanges(before, list))
	h.syncDNSNames(post, list, beforeNames, afterNames)

	// Access list rules are rendered statically into each dependent host's
	// nginx config, so the edit must fan out to every referencing host —
	// otherwise nginx silently keeps enforcing the stale allow/deny rules.
	if err := h.proxyHosts.RegenerateConfigsForAccessList(post, id); err != nil {
		return internalError(c, "apply access list changes to nginx", err)
	}

	return c.JSON(http.StatusOK, h.viewOf(c, list))
}

// Delete removes an access list by ID.
func (h *AccessListHandler) Delete(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	existing, err := h.repo.GetByID(ctx, id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if existing == nil {
		return notFoundError(c, "Access list")
	}

	// Capture dependents BEFORE the delete detaches them (the repo clears
	// proxy_hosts.access_list_id in the same transaction).
	hostIDs, err := h.proxyHosts.GetHostIDsByAccessList(ctx, id)
	if err != nil {
		return databaseError(c, "list access list dependents", err)
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		return databaseError(c, "delete access list", err)
	}
	post, cancel := afterAccessListCommit(ctx)
	defer cancel()
	h.audit.LogAccessListDeleted(service.ContextWithAudit(post, c), existing.Name)
	h.proxyHosts.RemoveAccessListHtpasswd(id)
	// The deleted list's domain files are emptied before the hosts are
	// regenerated: the next reload stops allowing them even if this fails.
	h.syncDNSNames(post, existing, accessListDNSNames(existing.Items), nil)

	// Regenerate dependent host configs so the deleted allow/deny rules stop
	// being enforced by the running nginx.
	if len(hostIDs) > 0 {
		if err := h.proxyHosts.RegenerateConfigsForHostIDs(post, hostIDs); err != nil {
			return internalError(c, "apply access list deletion to nginx", err)
		}
	}

	return noContentResponse(c)
}

// accessListApplyTimeout bounds what a list update or delete does after its
// commit: the audit, the domain files (up to 3 s of lookups) and the hosts'
// regeneration with its nginx -t and reload.
const accessListApplyTimeout = 2 * time.Minute

// afterAccessListCommit is the context of the work after a list's commit.
// It keeps the request's values but not its end: a client that leaves (a
// phone closed during the lookups) must not cut that work short, or nginx
// keeps the old rules, a removed address still allowed, and nothing
// retries.
func afterAccessListCommit(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), accessListApplyTimeout)
}

// accessListRulesRefused answers a save whose rules or domains were refused:
// 400 {error, field, code} for one rule (field is its request path) and for
// the domain limits, 400 {error} for the list's own fields. Anything else
// (the limit check could not read the database) is an internal error.
func accessListRulesRefused(c echo.Context, err error) error {
	var rule *model.AccessListItemError
	if errors.As(err, &rule) {
		return c.JSON(http.StatusBadRequest, accessListRuleError(rule.Message, rule.Field, rule.Code))
	}
	var limit *service.DNSLimitError
	if errors.As(err, &limit) {
		return c.JSON(http.StatusBadRequest, accessListRuleError(limit.Error(), limit.Field, "limit"))
	}
	if errors.Is(err, model.ErrInvalidInput) {
		return badRequestError(c, trimInvalidInputPrefix(err))
	}
	return internalError(c, "check the access list's domains", err)
}

// accessListRuleError is the 400 body of a refused rule. Every value is a
// string, as clients decode error bodies.
func accessListRuleError(message, field, code string) map[string]string {
	body := map[string]string{"error": scrubbedClientText(message), "field": field}
	if code != "" {
		body["code"] = code
	}
	return body
}

// checkDNSLimits asks the DNS service whether names may be scope's domains
// (refused only when a save raises a count above its limit).
func (h *AccessListHandler) checkDNSLimits(ctx context.Context, scope string, names []string) error {
	if h.dns == nil || len(names) == 0 {
		return nil
	}
	return h.dns.ValidateScopeNames(ctx, scope, names)
}

// syncDNSNames hands the list's domains to the DNS service once the list is
// saved and before the hosts' configs are regenerated: new names are looked
// up (at most 3 s) and the list's include files written, so a domain taken
// out stops matching at the next reload even if the regeneration
// fails. A failure does not fail the save: the next DNS
// check does the same from the database within one interval, and a new
// domain lets no one in until then (its include file is empty). The WARN
// line reaches the system log through the container log collector, when
// that is on. A list without domains before and after leaves the DNS
// service alone.
func (h *AccessListHandler) syncDNSNames(ctx context.Context, list *model.AccessList, before, after []string) {
	if h.dns == nil || (len(before) == 0 && len(after) == 0) {
		return
	}
	if err := h.dns.SyncScope(ctx, model.AccessListDNSScope(list.ID), after); err != nil {
		log.Printf("[DNSEntries] WARN: access list %q is saved, but its domain files were not updated (%v); the next DNS check updates them", list.Name, err)
	}
}

// accessListChanges describes an access list update for the audit log: the
// rules added and removed ("allow 192.0.2.0/24"; a domain rule, stored as
// deny all, as "allow <name> (domain)"), "moved_to_domain" for legacy rules
// that came back as domains (an old name that now works), "reordered" when
// the same rules now stand in another order (allow and deny are
// first-match), and, when they changed, the name (as "renamed") and
// satisfy_any as [before, after]. The audit service fills the entry's "name"
// with the list's current name, so a rename under that key would lose the
// old name.
func accessListChanges(before, after *model.AccessList) map[string]interface{} {
	details := map[string]interface{}{}
	rule := func(it model.AccessListItem) string {
		if it.Hostname != "" {
			return "allow " + it.Hostname + " (domain)"
		}
		return it.Directive + " " + it.Address
	}
	left := map[string]int{}
	for _, it := range before.Items {
		left[rule(it)]++
	}
	var added, addedDomains []string
	for _, it := range after.Items {
		if left[rule(it)] > 0 {
			left[rule(it)]--
			continue
		}
		added = append(added, rule(it))
		if it.Hostname != "" {
			addedDomains = append(addedDomains, it.Hostname)
		}
	}
	var removed []string
	legacyRemoved := map[string]bool{}
	for _, it := range before.Items {
		if left[rule(it)] > 0 {
			left[rule(it)]--
			removed = append(removed, rule(it))
			if it.Directive == "allow" && model.AccessListItemKind(it) == model.AccessListKindLegacy {
				legacyRemoved[model.NormalizeDNSName(it.Address)] = true
			}
		}
	}
	var moved []string
	for _, name := range addedDomains {
		if legacyRemoved[name] {
			moved = append(moved, name)
		}
	}
	if len(added) > 0 {
		details["added"] = added
	}
	if len(removed) > 0 {
		details["removed"] = removed
	}
	if len(moved) > 0 {
		details["moved_to_domain"] = moved
	}
	if len(added) == 0 && len(removed) == 0 {
		for i := range before.Items {
			if rule(before.Items[i]) != rule(after.Items[i]) {
				details["reordered"] = true
				break
			}
		}
	}
	if before.Name != after.Name {
		details["renamed"] = []string{before.Name, after.Name}
	}
	if before.SatisfyAny != after.SatisfyAny {
		details["satisfy_any"] = []bool{before.SatisfyAny, after.SatisfyAny}
	}
	accessListAuthChanges(details, before, after)
	return details
}
