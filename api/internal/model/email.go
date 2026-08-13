package model

import (
	"fmt"
	"net/mail"
	"strings"
)

// NormalizeEmail trims and lowercases an address, and rejects what an identity
// provider could never assert.
//
// It exists because an account's address is what SSO links an identity to
// (#240): a stored address with stray whitespace or mixed case would silently
// fail to match the provider's claim, and the operator would have nothing to go
// on. Storing the normalized form makes the stored value and the comparison
// agree by construction rather than by remembering to call lower() everywhere.
//
// Display names are refused on purpose: `mail.ParseAddress` happily accepts
// `Ada <ada@example.com>`, which would be stored whole and never match.
func NormalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("invalid email address: it is empty")
	}
	addr, err := mail.ParseAddress(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid email address")
	}
	if addr.Name != "" || addr.Address != trimmed {
		return "", fmt.Errorf("invalid email address: enter the address on its own, without a name")
	}
	// No dot is required in the domain: `me@lan`, `admin@localhost` and other
	// single-label domains are ordinary on a home network, which is who runs
	// this. Requiring a TLD here would reject the addresses these installs
	// actually use.
	if len(addr.Address) > 255 {
		return "", fmt.Errorf("invalid email address: it is longer than 255 characters")
	}
	return strings.ToLower(addr.Address), nil
}
