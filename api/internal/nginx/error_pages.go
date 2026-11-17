package nginx

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"nginx-proxy-guard/internal/model"
)

// CustomErrorPageRenderDir holds the operator's error pages (#335) as host
// configs name them. It sits under includes/, which nginx never loads as
// config, and the API writes it as it writes the other include files.
const CustomErrorPageRenderDir = "/etc/nginx/conf.d/includes/error_pages"

// customErrorPageCSP is sent with a custom page. The page is the operator's
// HTML on every proxied site's own origin: sandbox gives it an opaque origin
// and, with default-src 'none', no script runs, so it cannot read that site's
// cookies or storage. Styles, images and fonts may come from anywhere.
const customErrorPageCSP = "default-src 'none'; style-src * 'unsafe-inline'; img-src * data:; font-src * data:; frame-ancestors 'none'; sandbox"

func (m *Manager) customErrorPageDiskDir() string {
	return filepath.Join(m.configPath, "includes", "error_pages")
}

// customErrorPageSet is the pages that have a custom file on disk.
type customErrorPageSet map[int]bool

// customErrorPages reads which custom pages exist. The files are the state
// the configs follow: the API writes them from the database before it
// renders (SyncCustomErrorPages, ApplyCustomErrorPages).
func (m *Manager) customErrorPages() customErrorPageSet {
	set := customErrorPageSet{}
	for _, code := range model.CustomErrorPageStatuses {
		if st, err := os.Stat(filepath.Join(m.customErrorPageDiskDir(), strconv.Itoa(code)+".html")); err == nil && st.Mode().IsRegular() {
			set[code] = true
		}
	}
	return set
}

// serverErrorLocation is the internal location of a backend error page in
// host_common.conf: the built-in page, or the custom one with its CSP.
func (s customErrorPageSet) serverErrorLocation(code int) string {
	if !s[code] {
		return fmt.Sprintf("location = /error_%d.html { internal; auth_request off; root /etc/nginx/html; try_files /%d.html =%d; }", code, code, code)
	}
	return fmt.Sprintf("location = /error_%d.html { internal; auth_request off; root %s; try_files /%d.html =%d; add_header Content-Security-Policy \"%s\" always; }",
		code, CustomErrorPageRenderDir, code, code, customErrorPageCSP)
}

// blockedRoot is the root line of @blocked, the 403 page, with the CSP when
// the page is custom.
func (s customErrorPageSet) blockedRoot() string {
	if !s[403] {
		return "    root /etc/nginx/html;\n"
	}
	return fmt.Sprintf("    root %s;\n    add_header Content-Security-Policy \"%s\" always;\n", CustomErrorPageRenderDir, customErrorPageCSP)
}

// defaultServerErrorLocation is the internal location of an error page in the
// default server (zzz_default.conf).
func (s customErrorPageSet) defaultServerErrorLocation(code int) string {
	if !s[code] {
		return fmt.Sprintf("    location = /%d.html {\n        root /etc/nginx/html;\n        internal;\n    }", code)
	}
	return fmt.Sprintf("    location = /%d.html {\n        root %s;\n        internal;\n        add_header Content-Security-Policy \"%s\" always;\n    }", code, CustomErrorPageRenderDir, customErrorPageCSP)
}

// writeCustomErrorPageFiles makes the directory hold exactly pages, one file
// per status code, and leaves a file alone when it already holds that HTML.
func (m *Manager) writeCustomErrorPageFiles(pages []model.CustomErrorPage) error {
	want := map[int]string{}
	for _, p := range pages {
		if model.IsCustomErrorPageStatus(p.StatusCode) {
			want[p.StatusCode] = p.HTML
		}
	}
	for _, code := range model.CustomErrorPageStatuses {
		path := filepath.Join(m.customErrorPageDiskDir(), strconv.Itoa(code)+".html")
		html, ok := want[code]
		if !ok {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove custom error page %d: %w", code, err)
			}
			continue
		}
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, []byte(html)) {
			continue
		}
		// Workers read it as the nginx user, not the API's.
		if err := m.writeFileAtomic(path, []byte(html), 0644); err != nil {
			return fmt.Errorf("write custom error page %d: %w", code, err)
		}
	}
	return nil
}

// SyncCustomErrorPages writes the custom pages to disk at startup, before any
// config is rendered from them. It does not reload nginx.
func (m *Manager) SyncCustomErrorPages(pages []model.CustomErrorPage) error {
	return m.writeCustomErrorPageFiles(pages)
}

// ApplyCustomErrorPages puts pages on disk, renders host_common.conf and the
// default server for them, and reloads nginx. If nginx -t refuses the result,
// the previous files are put back and nginx keeps running as it was.
func (m *Manager) ApplyCustomErrorPages(ctx context.Context, pages []model.CustomErrorPage, directIPAction string) error {
	return m.executeWithLock(ctx, func() error {
		snapshot := map[string][]byte{}
		paths := []string{
			filepath.Join(m.configPath, "includes", "host_common.conf"),
			filepath.Join(m.configPath, "zzz_default.conf"),
		}
		for _, code := range model.CustomErrorPageStatuses {
			paths = append(paths, filepath.Join(m.customErrorPageDiskDir(), strconv.Itoa(code)+".html"))
		}
		for _, p := range paths {
			if b, err := os.ReadFile(p); err == nil {
				snapshot[p] = b
			}
		}
		restore := func() {
			for _, p := range paths {
				if b, ok := snapshot[p]; ok {
					if err := m.writeFileAtomic(p, b, 0644); err != nil {
						log.Printf("[ErrorPages] restore %s: %v", p, err)
					}
				} else {
					_ = os.Remove(p)
				}
			}
		}

		if err := m.writeCustomErrorPageFiles(pages); err != nil {
			restore()
			return err
		}
		if err := m.ensureHostCommonInclude(); err != nil {
			restore()
			return err
		}
		if err := m.GenerateDefaultServerConfig(ctx, directIPAction); err != nil {
			restore()
			return err
		}
		if err := m.testAndReloadNginx(ctx); err != nil {
			restore()
			return err
		}
		return nil
	})
}
