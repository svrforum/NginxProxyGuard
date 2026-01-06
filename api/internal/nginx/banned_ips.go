package nginx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// UpdateBannedIPs generates the banned_ips.conf file with all blocked IPs
func (m *Manager) UpdateBannedIPs(ctx context.Context, bannedIPs []string) error {
	// Lock globally to prevent race condition with other config operations
	return m.executeWithLock(ctx, func() error {
		includesPath := filepath.Join(m.configPath, "includes")

		// Ensure includes directory exists
		if err := os.MkdirAll(includesPath, 0755); err != nil {
			return fmt.Errorf("failed to create includes directory: %w", err)
		}

		// Generate banned_ips.conf content
		var content strings.Builder
		content.WriteString("# Auto-generated banned IPs - DO NOT EDIT\n")
		content.WriteString("# This file is managed by Nginx Proxy Guard\n\n")

		if len(bannedIPs) == 0 {
			content.WriteString("# No banned IPs\n")
		} else {
			for _, ip := range bannedIPs {
				content.WriteString(fmt.Sprintf("deny %s;\n", ip))
			}
		}

		// Write to file atomically
		configFile := filepath.Join(includesPath, "banned_ips.conf")
		if err := m.writeFileAtomic(configFile, []byte(content.String()), 0644); err != nil {
			return fmt.Errorf("failed to write banned_ips.conf: %w", err)
		}

		// Test and reload nginx to apply changes (within the same lock)
		if !m.skipTest {
			if err := m.testAndReloadNginx(ctx); err != nil {
				return fmt.Errorf("failed to reload nginx after updating banned IPs: %w", err)
			}
		}

		return nil
	})
}
