package service

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Finding the database container (D1). The database's data directory is not
// mounted in the API container, so its disk can only be measured from inside
// the container that runs it — which first has to be found.

const (
	defaultPGDataDir  = "/var/lib/postgresql/data"
	dockerCallTimeout = 5 * time.Second
)

// dockerRunner runs the docker CLI. Injected so tests need no Docker.
type dockerRunner func(ctx context.Context, args ...string) ([]byte, error)

// runDockerCLI runs `docker <args>` with a fixed argv and no shell. The
// timeout kills the CLI process; unlike statfs on a dead mount, that works.
func runDockerCLI(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerCallTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// containerNameRe is Docker's own charset for names. It also guarantees the
// name cannot be read as a flag.
var containerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

type dbLocator struct {
	run    dockerRunner
	env    string // NPG_DB_CONTAINER
	dbHost string // host part of DATABASE_URL
	lookup func(ctx context.Context, host string) ([]string, error)
}

// databaseHost extracts the host from a URL or key=value DSN.
func databaseHost(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		return u.Hostname()
	}
	for _, kv := range strings.Fields(dsn) {
		if v, ok := strings.CutPrefix(kv, "host="); ok {
			return strings.Trim(v, `'"`)
		}
	}
	return ""
}

func (l *dbLocator) running(ctx context.Context, name string) bool {
	if !containerNameRe.MatchString(name) {
		return false
	}
	// `container inspect`, not `inspect`: an image or volume named "db" must
	// not answer for a container.
	out, err := l.run(ctx, "container", "inspect", "-f", "{{.State.Running}}", "--", name)
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// locate names the container that serves DATABASE_URL, or explains why not
// with a reason code: db_container_not_found, db_external, docker_unavailable.
//
// Order: NPG_DB_CONTAINER; the host itself when it is a container name (the
// dev compose connects to "npg-db"); otherwise the container whose network
// address is what the host resolves to (the release compose connects to the
// service alias "db", which `docker container inspect` does not know). There
// is deliberately no hard-coded "npg-db" guess: on a box that also runs the
// e2e stack it would measure the wrong database.
func (l *dbLocator) locate(ctx context.Context) (name, reason string) {
	if l.env != "" {
		if l.running(ctx, l.env) {
			return l.env, ""
		}
		return "", "db_container_not_found"
	}
	h := l.dbHost
	if h == "" || strings.HasPrefix(h, "/") || h == "localhost" {
		return "", "db_container_not_found"
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return "", "db_container_not_found"
	}
	if l.running(ctx, h) {
		return h, ""
	}
	addrs, err := l.lookup(ctx, h)
	if err != nil || len(addrs) == 0 {
		return "", "db_container_not_found"
	}
	want := map[string]bool{}
	for _, a := range addrs {
		want[a] = true
	}
	ids, err := l.run(ctx, "ps", "-q", "--no-trunc")
	if err != nil {
		return "", "docker_unavailable"
	}
	idList := strings.Fields(string(ids))
	if len(idList) == 0 {
		return "", "db_external"
	}
	args := []string{"container", "inspect", "-f", "{{.Name}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}", "--"}
	out, err := l.run(ctx, append(args, idList...)...)
	if err != nil && len(out) == 0 {
		return "", "docker_unavailable"
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		nm, ips, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		for _, ip := range strings.Fields(ips) {
			if want[ip] {
				return strings.TrimPrefix(nm, "/"), ""
			}
		}
	}
	// Resolvable but no container here owns that address: a managed or
	// remote database. Its disk is not this host's to watch.
	return "", "db_external"
}

// validDataDir rejects anything that is not a plain absolute path. The value
// comes from the database, and it becomes one argv element of a docker exec.
func validDataDir(p string) bool {
	if !filepath.IsAbs(p) || len(p) > 1024 {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return filepath.Clean(p) == p
}
