package nginx

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"nginx-proxy-guard/internal/htpasswd"
	"nginx-proxy-guard/internal/model"
)

// HtpasswdRenderDir holds the htpasswd file of each access list with basic
// auth accounts (#387), as host configs name it. It sits under includes/, so
// the conf.d/*.conf glob never loads one as config.
const HtpasswdRenderDir = "/etc/nginx/conf.d/includes/htpasswd"

func htpasswdFileName(listID string) string {
	return strings.ReplaceAll(listID, "-", "_")
}

func (m *Manager) htpasswdDiskDir() string {
	return filepath.Join(m.configPath, "includes", "htpasswd")
}

// BasicAuth reports whether the host asks for one of its access list's basic
// auth accounts (#387). An auth provider (ForwardAuth) on the host wins: the
// API refuses the pair, since ForwardAuth's error_page 401 would send the
// password prompt to the provider's login, and a pair restored from a backup
// keeps ForwardAuth.
func (d ProxyHostConfigData) BasicAuth() bool {
	return d.AccessList != nil && len(d.AccessList.AuthUsers) > 0 && d.AuthProvider == nil
}

// HtpasswdPath is the htpasswd file of the host's access list.
func (d ProxyHostConfigData) HtpasswdPath() string {
	if d.AccessList == nil {
		return ""
	}
	return HtpasswdRenderDir + "/" + htpasswdFileName(d.AccessList.ID)
}

// htpasswdContent is the file nginx reads: one "username:hash" line per
// account. An account whose username or hash would not make exactly one such
// line (a row from before the API checked them, or an edited backup) is left
// out, so it cannot add a line of its own.
func htpasswdContent(list *model.AccessList) []byte {
	var b bytes.Buffer
	for _, u := range list.AuthUsers {
		if u.Username == "" || strings.ContainsAny(u.Username, ":\r\n\t ") || !htpasswd.IsHash(u.PasswordHash) {
			log.Printf("[WARN] Access list %s: account %q left out of the htpasswd file: its username or hash is not usable", list.ID, u.Username)
			continue
		}
		b.WriteString(u.Username)
		b.WriteByte(':')
		b.WriteString(u.PasswordHash)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// ensureAccessListHtpasswd writes the htpasswd file of the host's access list
// before the host config that names it, and leaves it alone when it already
// holds the same accounts. nginx reads the file on each request, not at
// reload, so a missing file would answer 500 rather than fail nginx -t.
func (m *Manager) ensureAccessListHtpasswd(data ProxyHostConfigData) error {
	if !data.BasicAuth() {
		return nil
	}
	path := filepath.Join(m.htpasswdDiskDir(), htpasswdFileName(data.AccessList.ID))
	content := htpasswdContent(data.AccessList)
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, content) {
		return nil
	}
	// Workers read it as the nginx user, not the API's.
	if err := m.writeFileAtomic(path, content, 0644); err != nil {
		return fmt.Errorf("write htpasswd file for access list %s: %w", data.AccessList.ID, err)
	}
	return nil
}

// RemoveAccessListHtpasswd deletes the htpasswd file of a deleted access list.
func (m *Manager) RemoveAccessListHtpasswd(listID string) error {
	err := os.Remove(filepath.Join(m.htpasswdDiskDir(), htpasswdFileName(listID)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
