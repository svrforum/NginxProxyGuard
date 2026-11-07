package model

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxInstanceNameLength is how many characters an instance name may have,
// the width of system_settings.instance_name.
const MaxInstanceNameLength = 32

// InstanceInfo is what the header shows about this NPG (#369): its version,
// the version of nginx it runs, and the name the operator gave it.
type InstanceInfo struct {
	Version      string `json:"version"`
	NginxVersion string `json:"nginx_version,omitempty"`
	InstanceName string `json:"instance_name"`
}

// NormalizeInstanceName trims an instance name and checks it: at most
// MaxInstanceNameLength characters and no control characters. An empty name
// shows none.
func NormalizeInstanceName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > MaxInstanceNameLength {
		return "", fmt.Errorf("instance_name may have at most %d characters", MaxInstanceNameLength)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", errors.New("instance_name may not contain control characters")
	}
	return name, nil
}
