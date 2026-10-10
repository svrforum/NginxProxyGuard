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
	// dbResolveTimeout bounds the check whether the database host resolves
	// again, which a provisional pick makes at most once per dbRecheckEvery.
	dbResolveTimeout = 2 * time.Second
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

// runningByName returns the canonical name of the running container that is
// called exactly name, or "" when there is none.
//
// `container inspect`, not `inspect`: an image or volume named "db" must not
// answer for a container. And the name it reports must be the one asked for:
// Docker also resolves an argument as a container-ID prefix, and the release
// compose's host "db" is two hex digits — any running container whose ID
// starts with "db" would otherwise answer, and its disk would be measured.
func (l *dbLocator) runningByName(ctx context.Context, name string) string {
	if !containerNameRe.MatchString(name) {
		return ""
	}
	out, err := l.run(ctx, "container", "inspect", "-f", "{{.Name}}|{{.State.Running}}", "--", name)
	if err != nil {
		return ""
	}
	got, running, _ := strings.Cut(strings.TrimSpace(string(out)), "|")
	if strings.TrimPrefix(got, "/") != name || running != "true" {
		return ""
	}
	return name
}

// locate names the container that serves DATABASE_URL, or explains why not
// with a reason code: db_container_not_found, db_external, docker_unavailable.
//
// Order: NPG_DB_CONTAINER; then, when the host resolves, the container whose
// network address is what it resolves to (the release compose connects to the
// service alias "db", which `docker container inspect` does not know; the dev
// compose's "npg-db" resolves to npg-db's own address); only a host that does
// not resolve from here is taken as a container name. A container that is
// merely called like a resolvable host is not the database: another stack's
// container_name "db" would otherwise answer for the release compose's alias
// and its disk would be measured. There is deliberately no hard-coded "npg-db"
// guess either: on a box that also runs the e2e stack it would measure the
// wrong database.
//
// provisional is true for a container taken by its name because the host did
// not resolve. That happens while the database container is restarting or
// stopped (Docker's DNS does not answer for it then), which is also when
// another stack's container called like the host is the one found: the
// caller keeps such a pick only until the host resolves again.
func (l *dbLocator) locate(ctx context.Context) (name, reason string, provisional bool) {
	if l.env != "" {
		if n := l.runningByName(ctx, l.env); n != "" {
			return n, "", false
		}
		return "", "db_container_not_found", false
	}
	h := l.dbHost
	if h == "" || strings.HasPrefix(h, "/") || h == "localhost" {
		return "", "db_container_not_found", false
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return "", "db_container_not_found", false
	}
	var addrs []string
	if l.lookup != nil {
		if a, err := l.lookup(ctx, h); err == nil {
			addrs = a
		}
	}
	if len(addrs) == 0 {
		if n := l.runningByName(ctx, h); n != "" {
			return n, "", true
		}
		return "", "db_container_not_found", false
	}
	want := map[string]bool{}
	for _, a := range addrs {
		want[a] = true
	}
	ids, err := l.run(ctx, "ps", "-q", "--no-trunc")
	if err != nil {
		return "", "docker_unavailable", false
	}
	idList := strings.Fields(string(ids))
	if len(idList) == 0 {
		return "", "db_external", false
	}
	args := []string{"container", "inspect", "-f", "{{.Name}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}", "--"}
	out, err := l.run(ctx, append(args, idList...)...)
	if err != nil && len(out) == 0 {
		return "", "docker_unavailable", false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		nm, ips, ok := strings.Cut(line, "|")
		nm = strings.TrimPrefix(nm, "/")
		if !ok || !containerNameRe.MatchString(nm) {
			continue
		}
		for _, ip := range strings.Fields(ips) {
			if want[ip] {
				return nm, "", false
			}
		}
	}
	// Resolvable but no container here owns that address: a managed or
	// remote database. Its disk is not this host's to watch.
	return "", "db_external", false
}

// resolves reports whether the database host resolves from here now, within
// dbResolveTimeout.
func (l *dbLocator) resolves(ctx context.Context) bool {
	if l.lookup == nil || l.dbHost == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, dbResolveTimeout)
	defer cancel()
	addrs, err := l.lookup(ctx, l.dbHost)
	return err == nil && len(addrs) > 0
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
