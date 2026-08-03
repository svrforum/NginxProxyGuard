package model

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateNotificationTarget checks where a notification would actually be sent.
//
// The URL is operator-supplied and NPG fetches it from inside the operator's own
// network, which makes it an SSRF vector aimed at the LAN and at
// 169.254.169.254. A private destination is therefore refused unless the channel
// opts in — the opt-in exists because a LAN ntfy or Gotify instance is a
// perfectly legitimate receiver for a home server.
//
// ValidateProviderURL in auth_provider.go is NOT a substitute: it checks only
// the scheme prefix and nginx-unsafe characters, and would accept
// http://169.254.169.254/ without complaint. (#221)
func ValidateNotificationTarget(rawURL string, allowPrivate bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("invalid url: required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid url: not a URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid url: must be http or https")
	}
	if IsPrivateHost(u.Hostname()) && !allowPrivate {
		return fmt.Errorf("invalid url: %s is on a private network — turn on 'allow a private receiver' for this channel to send there", u.Hostname())
	}
	return nil
}
