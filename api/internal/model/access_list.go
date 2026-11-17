package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// AccessList represents a reusable access control list
type AccessList struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	SatisfyAny  bool             `json:"satisfy_any"` // true = any rule match, false = all must match
	PassAuth    bool             `json:"pass_auth"`   // Pass the basic auth credentials on to the backend (#387)
	Items       []AccessListItem `json:"items,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`

	// AuthUsers are the basic auth accounts (#387).
	AuthUsers []AccessListAuthUser `json:"auth_users,omitempty"`
}

// AccessListItem represents a single allow/deny rule
type AccessListItem struct {
	ID           string    `json:"id"`
	AccessListID string    `json:"access_list_id"`
	Directive    string    `json:"directive"` // "allow" or "deny"
	Address      string    `json:"address"`   // IP, CIDR, or "all"
	Description  string    `json:"description,omitempty"`
	SortOrder    int       `json:"sort_order"`
	CreatedAt    time.Time `json:"created_at"`

	// Hostname is set on a domain row (#320). Such a row is stored as
	// (deny, all, hostname), which every version without domain rows renders
	// as "deny all": closed. Only the API DTO shows it as an allow row with
	// kind "hostname"; code that does not know Hostname keeps the row closed.
	Hostname string `json:"-"`
}

// CreateAccessListRequest is the request to create an access list
type CreateAccessListRequest struct {
	Name        string                       `json:"name" validate:"required,min=1,max=255"`
	Description string                       `json:"description,omitempty"`
	SatisfyAny  *bool                        `json:"satisfy_any,omitempty"`
	PassAuth    *bool                        `json:"pass_auth,omitempty"`
	Items       []CreateAccessListItemRequest `json:"items,omitempty"`

	AuthUsers []AccessListAuthUserRequest `json:"auth_users,omitempty"`
}

// CreateAccessListItemRequest is the request to create an access list item.
// Kind says what Address holds: "address" (an IP address, a CIDR range or
// all; the default), "hostname" (a domain, allow only) or "legacy" (a rule
// an older version saved, sent back as it was read). Hostname is never read
// from a request: the Validate functions below set it for a domain rule,
// which the repository stores as (deny, all, hostname).
type CreateAccessListItemRequest struct {
	Directive   string `json:"directive" validate:"required,oneof=allow deny"`
	Address     string `json:"address" validate:"required"`
	Description string `json:"description,omitempty"`
	SortOrder   int    `json:"sort_order,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Hostname    string `json:"-"`
}

// UpdateAccessListRequest is the request to update an access list
type UpdateAccessListRequest struct {
	Name        *string                       `json:"name,omitempty"`
	Description *string                       `json:"description,omitempty"`
	SatisfyAny  *bool                         `json:"satisfy_any,omitempty"`
	PassAuth    *bool                         `json:"pass_auth,omitempty"`
	Items       []CreateAccessListItemRequest `json:"items,omitempty"`

	// AuthUsers replaces the accounts when sent; absent keeps them.
	AuthUsers []AccessListAuthUserRequest `json:"auth_users,omitempty"`
}

// AccessListListResponse is the response for listing access lists
type AccessListListResponse struct {
	Data       []AccessList `json:"data"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	TotalPages int          `json:"total_pages"`
}

// An access list is written into the nginx config of every proxy host that
// uses it: each rule as an "allow" or "deny" line, the list's name and each
// rule's description as "#" comments.

// accessListRuleMaxDescription bounds a rule description, which sits in a "#"
// comment after its rule: nginx refuses a comment line of 4 KB or more, and
// the config generator writes at most 1 KB of one.
const accessListRuleMaxDescription = 1000

// IsAccessListDirective reports whether d is a directive an access list rule
// can use.
func IsAccessListDirective(d string) bool {
	return d == "allow" || d == "deny"
}

// IsAccessListAddress reports whether a is an address nginx's allow and deny
// directives take: an IP address, a CIDR range, or "all".
func IsAccessListAddress(a string) bool {
	return a == "all" || IsIPOrCIDR(a)
}

// Kinds of an access list rule in the API. The table has no kind column: a
// domain rule is stored as (deny, all, hostname), which versions without
// domains read as deny all; a legacy rule is a name an older version saved
// in address, with no hostname; an address rule is the rest.
const (
	AccessListKindAddress  = "address"
	AccessListKindHostname = "hostname"
	AccessListKindLegacy   = "legacy"
)

// What the generated config does with a legacy rule (nginx accessListRules):
// an allow is left out, anything else is written as deny all in its place.
const (
	AccessListEffectIgnored = "ignored"
	AccessListEffectDenyAll = "deny_all"
)

// Codes of an AccessListItemError besides the DNSNameError codes, which a
// domain that breaks a name rule carries.
const (
	AccessListCodeHostnameNeedsKind   = "hostname_needs_kind"
	AccessListCodeDenyHostname        = "deny_hostname"
	AccessListCodeDuplicateHostname   = "duplicate_hostname"
	AccessListCodeDenyAllWithHostname = "deny_all_with_hostname"
	AccessListCodeLegacyNotInList     = "legacy_not_in_list"
)

// AccessListItemError is a refused rule. Field is its path by its position
// in the request ("items[2].address"), Code a machine code for clients (""
// for the plain directive, address and description checks), and Message the
// sentence, which starts with Field.
type AccessListItemError struct {
	Field   string
	Code    string
	Message string
}

func (e *AccessListItemError) Error() string { return ErrInvalidInput.Error() + ": " + e.Message }

// Unwrap makes errors.Is(err, ErrInvalidInput) match.
func (e *AccessListItemError) Unwrap() error { return ErrInvalidInput }

func accessListItemError(field, code, format string, args ...interface{}) *AccessListItemError {
	return &AccessListItemError{Field: field, Code: code, Message: fmt.Sprintf(format, args...)}
}

// AccessListItemKind returns the kind of a stored rule.
func AccessListItemKind(it AccessListItem) string {
	switch {
	case it.Hostname != "":
		return AccessListKindHostname
	case IsAccessListDirective(it.Directive) && IsAccessListAddress(strings.TrimSpace(it.Address)):
		return AccessListKindAddress
	}
	return AccessListKindLegacy
}

// AccessListLegacyEffect returns what the config does with a legacy rule.
func AccessListLegacyEffect(it AccessListItem) string {
	if it.Directive == "allow" {
		return AccessListEffectIgnored
	}
	return AccessListEffectDenyAll
}

// ValidateCreateAccessListRequest checks what a new access list writes into
// the config and puts its rules in their stored form and order
// (normalizeAccessListItems). Whether the name is present and short enough
// is the handler's check.
func ValidateCreateAccessListRequest(req *CreateAccessListRequest) error {
	if err := ValidateSingleLine("name", req.Name, 0); err != nil {
		return err
	}
	if err := ValidateSingleLine("description", req.Description, 0); err != nil {
		return err
	}
	items, err := normalizeAccessListItems(req.Items, nil)
	if err != nil {
		return err
	}
	req.Items = items
	return ValidateAccessListAuthUsers(req.AuthUsers, nil)
}

// ValidateUpdateAccessListRequest checks the fields an update sends. stored
// are the list's rules before the update: a rule sent back as it was read
// keeps what it is (normalizeAccessListItems).
func ValidateUpdateAccessListRequest(req *UpdateAccessListRequest, stored []AccessListItem) error {
	if req.Name != nil {
		if err := ValidateSingleLine("name", *req.Name, 0); err != nil {
			return err
		}
	}
	if req.Description != nil {
		if err := ValidateSingleLine("description", *req.Description, 0); err != nil {
			return err
		}
	}
	items, err := normalizeAccessListItems(req.Items, stored)
	if err != nil {
		return err
	}
	req.Items = items
	// The accounts are checked by the handler with the stored ones
	// (ValidateAccessListAuthUsers): an account sent without a password keeps
	// its stored hash.
	return nil
}

// normalizeAccessListItems checks each rule in request order and returns the
// rules as they are stored. An address is trimmed of surrounding whitespace.
//
// Only kind "hostname" makes a domain (allow only), stored as (deny, all,
// name) with the name lower-cased and one trailing dot dropped. Kind
// "address" takes an IP address, a CIDR range or all. Kind "legacy" sends a
// rule an older version saved back as it was read: it must equal a stored
// legacy rule (same directive and address) and stays that rule as it is; a
// legacy rule the list does not hold is refused. A rule without kind is an
// address, or one of two rules an older client sends back as it read them:
// one equal to a stored legacy rule stays that legacy rule, as often as the
// list holds that rule, and an allow of a domain the list has stays that
// domain. A legacy rule and a domain can both read allow <name>; the legacy
// rule is read first, so a list sent back as it was read keeps both. So no
// save turns an old name into a working domain unless the client asks for
// it.
//
// A domain twice, or next to a rule that denies everyone before the domains
// are checked (deny all, or a legacy deny, which the config writes as deny
// all), is refused; the error names that rule by its request
// position. The rules come back in the order nginx checks them: by
// (sort_order, request position), address and legacy rules first, domains
// after, sort_order renumbered from 0. nil stays nil (an update that keeps
// the rules); an empty list stays empty (an update that clears them).
func normalizeAccessListItems(in []CreateAccessListItemRequest, stored []AccessListItem) ([]CreateAccessListItemRequest, error) {
	if in == nil {
		return nil, nil
	}
	storedNames := map[string]bool{}
	storedLegacy := map[string]bool{}
	// legacyLeft counts the stored legacy rules that rules without kind have
	// not matched yet.
	legacyLeft := map[string]int{}
	for _, it := range stored {
		switch AccessListItemKind(it) {
		case AccessListKindHostname:
			storedNames[it.Hostname] = true
		case AccessListKindLegacy:
			key := it.Directive + " " + strings.TrimSpace(it.Address)
			storedLegacy[key] = true
			legacyLeft[key]++
		}
	}

	items := make([]CreateAccessListItemRequest, len(in))
	names := map[string]bool{}
	for i, item := range in {
		field := fmt.Sprintf("items[%d]", i)
		item.Address = strings.TrimSpace(item.Address)
		item.Hostname = ""
		if !IsAccessListDirective(item.Directive) {
			return nil, accessListItemError(field+".directive", "", "%s.directive must be allow or deny", field)
		}
		kind, err := classifyAccessListItem(&item, field, storedNames, storedLegacy, legacyLeft)
		if err != nil {
			return nil, err
		}
		item.Kind = kind
		if err := ValidateSingleLine(field+".description", item.Description, accessListRuleMaxDescription); err != nil {
			return nil, &AccessListItemError{Field: field + ".description", Message: strings.TrimPrefix(err.Error(), ErrInvalidInput.Error()+": ")}
		}
		if kind == AccessListKindHostname {
			if names[item.Hostname] {
				return nil, accessListItemError(field+".address", AccessListCodeDuplicateHostname, "%s.address: %s is already in this list", field, item.Hostname)
			}
			names[item.Hostname] = true
		}
		items[i] = item
	}

	if len(names) > 0 {
		for i, item := range items {
			if item.Directive == "deny" && (item.Kind == AccessListKindLegacy || (item.Kind == AccessListKindAddress && item.Address == "all")) {
				field := fmt.Sprintf("items[%d].address", i)
				return nil, accessListItemError(field, AccessListCodeDenyAllWithHostname,
					"%s: this rule denies everyone before the domains of this list are checked (they come after the address rules), so they would never match; remove it, the list ends in deny all anyway", field)
			}
		}
	}
	return orderAccessListItems(items), nil
}

// classifyAccessListItem returns the kind of a request rule and puts a domain
// into its stored form (normalizeAccessListItems).
func classifyAccessListItem(item *CreateAccessListItemRequest, field string, storedNames, storedLegacy map[string]bool, legacyLeft map[string]int) (string, error) {
	switch item.Kind {
	case AccessListKindHostname:
		if item.Directive != "allow" {
			return "", accessListItemError(field+".directive", AccessListCodeDenyHostname, "%s.directive: a domain can only be allowed, not denied", field)
		}
		return accessListDomain(item, field)
	case AccessListKindLegacy:
		if storedLegacy[item.Directive+" "+item.Address] {
			return AccessListKindLegacy, nil
		}
		return "", accessListItemError(field+".address", AccessListCodeLegacyNotInList,
			"%s.address: this list has no old rule %q; kind legacy only keeps a stored rule as it was read", field, item.Directive+" "+item.Address)
	case "", AccessListKindAddress:
	default:
		return "", accessListItemError(field+".kind", "", "%s.kind must be address, hostname or legacy", field)
	}

	if IsAccessListAddress(item.Address) {
		return AccessListKindAddress, nil
	}
	name := NormalizeDNSName(item.Address)
	if item.Kind == "" {
		// An older client sends a rule back without kind. Each stored
		// legacy rule is matched once: a legacy rule that reads the same as
		// a domain of the list leaves the next copy to the domain.
		if key := item.Directive + " " + item.Address; legacyLeft[key] > 0 {
			legacyLeft[key]--
			return AccessListKindLegacy, nil
		}
		if item.Directive == "allow" && storedNames[name] {
			return accessListDomain(item, field)
		}
	}
	if ValidateDNSName(name) == nil {
		if item.Directive == "deny" {
			return "", accessListItemError(field+".directive", AccessListCodeDenyHostname, "%s.directive: a domain can only be allowed, not denied", field)
		}
		return "", accessListItemError(field+".address", AccessListCodeHostnameNeedsKind, "%s.address: a domain needs kind=hostname", field)
	}
	return "", accessListItemError(field+".address", "", "%s.address %q must be an IP address, a CIDR range or all", field, item.Address)
}

// accessListDomain checks a domain rule's name and puts the rule in its
// stored form, (deny, all, name).
func accessListDomain(item *CreateAccessListItemRequest, field string) (string, error) {
	name := NormalizeDNSName(item.Address)
	if err := ValidateDNSName(name); err != nil {
		code := ""
		if ne, ok := IsDNSNameError(err); ok {
			code = ne.Code
		}
		return "", accessListItemError(field+".address", code, "%s.address: %s", field, err.Error())
	}
	item.Directive, item.Address, item.Hostname = "deny", "all", name
	return AccessListKindHostname, nil
}

// orderAccessListItems returns items in the order nginx checks them and
// renumbers sort_order from 0 (normalizeAccessListItems).
func orderAccessListItems(items []CreateAccessListItemRequest) []CreateAccessListItemRequest {
	order := make([]int, len(items))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return items[order[a]].SortOrder < items[order[b]].SortOrder })
	out := make([]CreateAccessListItemRequest, 0, len(items))
	for _, domains := range []bool{false, true} {
		for _, i := range order {
			if (items[i].Kind == AccessListKindHostname) == domains {
				out = append(out, items[i])
			}
		}
	}
	for i := range out {
		out[i].SortOrder = i
	}
	return out
}
