package nginx

import (
	"log"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"nginx-proxy-guard/internal/model"
)

// The API checks the values below before it saves them, but the renderer also
// reads rows saved before those checks existed and rows restored from a
// backup. Each value goes through one of these functions on its way into a
// template, so that whatever a stored value holds, it stays inside its own
// comment, quoted argument or directive. A value the API accepts comes out
// exactly as it went in, so configs built from such values do not change.

// maxCommentText bounds each text written into a "#" comment. nginx reads a
// comment through the same 4096-byte buffer as a token and fails nginx -t
// ("too long parameter") on a longer one, and a line can hold two such texts
// (a Block Exploits rule's name and category). Every field the templates write
// into a comment is shorter than this when the API accepts it.
const maxCommentText = 1024

// commentText returns s for the rest of a "#" comment line: on one line (see
// model.SingleLine) and at most maxCommentText bytes, cut at a character
// boundary.
func commentText(s string) string {
	s = model.SingleLine(s)
	if len(s) <= maxCommentText {
		return s
	}
	cut := maxCommentText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// headerValue returns s for the double-quoted value of an add_header
// directive. Line breaks and control characters become a space, so the value
// stays one header line, and a double quote or a backslash is escaped, which
// nginx's tokenizer reads back as the character itself: a Permissions-Policy
// quotes its origins (geolocation=(self "https://a.example.com")), and that
// quote used to end the argument. "$" is left alone: add_header expands
// variables, and a nonce such as $request_id depends on it.
func headerValue(s string) string {
	s = model.SingleLine(s)
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// accessListRules returns the rules of list that can be written as an allow
// or deny line: the directive allow or deny and the address, trimmed, an IP
// address, a CIDR range or "all". Such a rule never worked otherwise: nginx
// refused the config it was in, which kept the whole host from loading. A
// rule that is not usable is logged and fails closed: an allow rule is left
// out, so the list's final "deny all" still applies to that address; any other
// rule becomes "deny all" in its place, because leaving out a deny would let
// an allow after it admit the address the deny was meant to stop.
//
// A domain row (#320: Hostname set, stored as deny all) is not a rule here.
// accessListDNSIncludes writes it as an include line after these rules. A
// domain row whose file path cannot be built (a name that breaks the name
// rules, or a list ID that is not a UUID) is written as "deny all" in its
// place, as versions without domain rows write every domain row.
func accessListRules(list *model.AccessList) []model.AccessListItem {
	if list == nil {
		return nil
	}
	rules := make([]model.AccessListItem, 0, len(list.Items))
	for _, item := range list.Items {
		if item.Hostname != "" {
			if accessListDNSPath(list, item) != "" {
				continue // an include line (accessListDNSIncludes)
			}
			warnSkippedOnce("access list "+list.ID+" domain "+item.ID+" "+item.Hostname,
				"[DNSEntries] WARN: Access list %s: domain entry %.80q is not a usable domain name, so it is written as \"deny all\" in its place. Edit the access list to correct or remove it.",
				list.ID, item.Hostname)
			rules = append(rules, model.AccessListItem{ID: item.ID, Directive: "deny", Address: "all"})
			continue
		}
		address := strings.TrimSpace(item.Address)
		if !model.IsAccessListDirective(item.Directive) || !model.IsAccessListAddress(address) {
			if item.Directive == "allow" {
				warnSkippedOnce("access list "+list.ID+" rule "+item.ID+" "+item.Directive+" "+item.Address,
					"[WARN] Access list %s: rule %q %q is not \"allow\" or \"deny\" with an IP address, a CIDR range or \"all\", so it is left out of the nginx config. Edit the access list to correct or remove it.",
					list.ID, item.Directive, item.Address)
				continue
			}
			warnSkippedOnce("access list "+list.ID+" rule "+item.ID+" "+item.Directive+" "+item.Address,
				"[WARN] Access list %s: rule %q %q is not \"allow\" or \"deny\" with an IP address, a CIDR range or \"all\", so it is written as \"deny all\" in its place. Edit the access list to correct or remove it.",
				list.ID, item.Directive, item.Address)
			rules = append(rules, model.AccessListItem{ID: item.ID, Directive: "deny", Address: "all"})
			continue
		}
		item.Address = address
		rules = append(rules, item)
	}
	return rules
}

// uriBlockRules returns the URI block rules whose pattern nginx reads as
// exactly one location argument on the location's line
// (model.RenderableURIBlockPattern, which describes where that boundary lies),
// with the pattern trimmed of the whitespace nginx skipped around it anyway, so
// a pattern nginx read as one argument before is written as it was. Any other
// rule is left out and logged: written as it is, its pattern would have ended
// the location's argument early, or run onto another line.
func uriBlockRules(rules []model.URIBlockRule) []model.URIBlockRule {
	out := make([]model.URIBlockRule, 0, len(rules))
	for _, rule := range rules {
		pattern, ok := model.RenderableURIBlockPattern(rule.Pattern)
		if !ok {
			warnSkippedOnce("uri block rule "+rule.ID+" "+rule.Pattern,
				"[WARN] URI block rule %s: pattern %.200q cannot be written as an nginx location, so the rule is left out of the config. Edit the rule to correct or remove it.",
				rule.ID, rule.Pattern)
			continue
		}
		rule.Pattern = pattern
		out = append(out, rule)
	}
	return out
}

// renderableGeo returns g with the country codes and priority-allow addresses
// the templates can write into their if conditions and geo block, normalized
// as the API saves them, and g itself when every entry already is.
//
// A country goes into the regex of a quoted condition (^(KR|CN)$) and is
// written as model.NormalizeCountryCode gives it: in upper case, the case the
// GeoIP lookup gives, so a code stored in lower case or with spaces around it
// matches as it was meant to, and any two letters or "--" are kept (XK is a
// code the lookup gives that is not on the country picker's list). Anything
// else is left out.
//
// An address goes into the host's priority allow geo block ($npg_prio_<id>)
// and the @ipMatch list of the host's ModSecurity file. It is written as
// model.NormalizeIPOrCIDR gives it after the whitespace around it is removed,
// once for each network (networkOf: the first of 192.0.2.1 and 192.0.2.1/32),
// and left out unless it is then an IP address or a CIDR range.
//
// What is left out is logged. It is not a code the lookup gives or an
// address: nginx cannot read it as a network in the geo block, ModSecurity
// refused it in @ipMatch, and in the country regex it changed what the
// condition matches.
func renderableGeo(hostID string, g *model.GeoRestriction) *model.GeoRestriction {
	if g == nil {
		return nil
	}
	countries := renderableCountries(hostID, g.Countries)
	allowed := renderableAllowedIPs(hostID, g.AllowedIPs)
	if slices.Equal(countries, g.Countries) && slices.Equal(allowed, g.AllowedIPs) {
		return g
	}
	geo := *g
	geo.Countries = countries
	geo.AllowedIPs = allowed
	return &geo
}

// geoWithOwnAuthRequest blocks rather than challenges the visitors a host's
// geo restriction refuses when location / of the host already has an
// auth_request: ForwardAuth's, or one at the top level of a legacy Advanced
// Config (refused since v2.25.0, but kept by hosts saved before then and by
// restored backups). location / takes one auth_request and the challenge gate
// needs it. Next to ForwardAuth nginx -t refused the config, so a GeoIP
// challenge, or a global GeoIP default in challenge mode that the host
// inherits, could not be saved (500, #341). Next to the legacy login nginx -t
// refused it as well, or, with locations in the Advanced Config, the gate
// replaced the login on location /. The cloud provider challenge blocks on
// such a host the same way (CloudChallenge).
func geoWithOwnAuthRequest(host *model.ProxyHost, g *model.GeoRestriction, authProvider bool) *model.GeoRestriction {
	if g == nil || !g.ChallengeMode {
		return g
	}
	switch {
	case authProvider:
		warnSkippedOnce("geo challenge "+host.ID,
			"[WARN] Host %s: GeoIP challenge mode cannot run next to ForwardAuth (both need the auth_request of location /), so the visitors the geo restriction refuses get 403 instead of the challenge.",
			host.ID)
	case advancedConfigHasTopLevel(host.AdvancedConfig, "auth_request"):
		warnSkippedOnce("geo challenge "+host.ID,
			"[WARN] Host %s: GeoIP challenge mode cannot run next to the auth_request in its Advanced Config (both need the auth_request of location /), so the visitors the geo restriction refuses get 403 instead of the challenge.",
			host.ID)
	default:
		return g
	}
	geo := *g
	geo.ChallengeMode = false
	return &geo
}

// renderableCountries returns the country codes in upper case, leaving out
// what is not a country code (see renderableGeo).
func renderableCountries(hostID string, countries []string) []string {
	out := countries[:0:0]
	for _, c := range countries {
		code, ok := model.NormalizeCountryCode(c)
		if !ok {
			warnSkippedOnce("geo country "+hostID+" "+c,
				"[WARN] Host %s: geo restriction country %.40q is not a two-letter country code, so it is left out of the nginx config. Edit the geo restriction to correct or remove it.",
				hostID, c)
			continue
		}
		out = append(out, code)
	}
	return out
}

// renderableAllowedIPs returns the priority-allow entries that are an IP
// address or a CIDR range, normalized and without duplicates (see
// renderableGeo).
func renderableAllowedIPs(hostID string, ips []string) []string {
	out := ips[:0:0]
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		normalized, ok := model.NormalizeIPOrCIDR(strings.TrimSpace(ip))
		if !ok {
			warnSkippedOnce("geo allowed ip "+hostID+" "+ip,
				"[WARN] Host %s: priority allow entry %.60q is not an IP address or CIDR range, so it is left out of the nginx config. Edit the geo restriction to correct or remove it.",
				hostID, ip)
			continue
		}
		if key := networkOf(normalized); seen[key] {
			continue // a geo block warns about a network listed twice
		} else {
			seen[key] = true
		}
		out = append(out, normalized)
	}
	return out
}

// networkOf returns the network an entry normalized by model.NormalizeIPOrCIDR
// names, a bare address being the network of that address alone (/32, /128),
// so that 192.0.2.1 and 192.0.2.1/32 compare equal.
func networkOf(normalized string) string {
	if p, err := netip.ParsePrefix(normalized); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(normalized); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return normalized
}

// renderableBans returns the bans whose address, without the whitespace
// around it, is an IP address or a CIDR range, with the address written that
// way. Each address is the network of a line in the host's banned-IP geo
// block. Any other ban is left out and logged: nginx did not read it as one
// network, so it either failed nginx -t for every host the ban covers ("all",
// which the API accepts, or an address with a quote or a ";" in it), or the
// rest of it was read as more of the geo block, or of the config after it.
func renderableBans(bans []model.BannedIP) []model.BannedIP {
	out := bans[:0:0]
	for _, ban := range bans {
		address := strings.TrimSpace(ban.IPAddress)
		if !model.IsIPOrCIDR(address) {
			warnSkippedOnce("ban "+ban.ID+" "+ban.IPAddress,
				"[WARN] Ban %s: address %.60q is not an IP address or CIDR range, so it is left out of the nginx config. Unban it, and ban the address again if it is still needed.",
				ban.ID, ban.IPAddress)
			continue
		}
		ban.IPAddress = address
		out = append(out, ban)
	}
	return out
}

// renderableURIBlock returns ub with only the exception IPs that, without the
// whitespace around them, are an IP address or a CIDR range, and ub itself
// when its list needs no change. ub holds the exception IPs of the host's URI
// block and of the global one, and each is written into the host's geo block
// of exception addresses ($npg_uri_exc_<id>), normalized
// (model.NormalizeIPOrCIDR) and once for each network (networkOf). Any other
// entry is left out and logged. It named no client's address, and nginx cannot read it as a
// network in the geo block. An entry with spaces around it, which the API
// accepts, never matched; written without them now, it does.
func renderableURIBlock(hostID string, ub *model.URIBlock) *model.URIBlock {
	if ub == nil {
		return nil
	}
	ips := ub.ExceptionIPs[:0:0]
	seen := make(map[string]bool, len(ub.ExceptionIPs))
	for _, ip := range ub.ExceptionIPs {
		normalized, ok := model.NormalizeIPOrCIDR(strings.TrimSpace(ip))
		if !ok {
			warnSkippedOnce("uri block exception ip "+hostID+" "+ip,
				"[WARN] Host %s: URI block exception IP %.60q is not an IP address or CIDR range, so it is left out of the nginx config. Edit the exception IPs of the host's URI block, or of the global URI block, to correct or remove it.",
				hostID, ip)
			continue
		}
		if key := networkOf(normalized); seen[key] {
			continue // a geo block warns about a network listed twice
		} else {
			seen[key] = true
		}
		ips = append(ips, normalized)
	}
	if slices.Equal(ips, ub.ExceptionIPs) {
		return ub
	}
	block := *ub
	block.ExceptionIPs = ips
	return &block
}

// skippedWarned holds the values already named in a warning above, so each is
// logged once per process rather than at every regeneration.
var skippedWarned sync.Map

func warnSkippedOnce(key, format string, args ...any) {
	if _, seen := skippedWarned.LoadOrStore(key, struct{}{}); seen {
		return
	}
	log.Printf(format, args...)
}
