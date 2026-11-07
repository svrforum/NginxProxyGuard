package nginx

import (
	"fmt"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// URIBlockLocation is a URI block rule as the host's config writes it: a
// location, and the geo variable that holds the rule's own exception
// addresses (#343), "" when the rule has none or is off.
type URIBlockLocation struct {
	model.URIBlockRule
	ExceptionVar string
}

// URIBlockLocations returns the rules of the host's URI block that the config
// writes as locations (uriBlockRules), none when the block is off.
// access_list.conf defines each rule's geo variable and _security.conf tests
// it in the rule's location. Both read this list, so they agree on the names,
// which number the rules in the order they are written.
func (d ProxyHostConfigData) URIBlockLocations() []URIBlockLocation {
	if d.URIBlock == nil || !d.URIBlock.Enabled || d.Host == nil {
		return nil
	}
	rules := uriBlockRules(d.URIBlock.Rules)
	locations := make([]URIBlockLocation, len(rules))
	for i, rule := range rules {
		locations[i].URIBlockRule = rule
		if rule.Enabled && len(rule.ExceptionIPs) > 0 {
			locations[i].ExceptionVar = fmt.Sprintf("npg_uri_rule_exc_%s_%d", strings.ReplaceAll(d.Host.ID, "-", "_"), i)
		}
	}
	return locations
}
