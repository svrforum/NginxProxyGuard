package nginx

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

const (
	// nginxVersionTTL is how long a version read is kept. It changes only
	// when the nginx container is replaced, which usually restarts the API
	// as well.
	nginxVersionTTL = time.Hour
	// nginxVersionTimeout bounds one `docker exec ... nginx -v`.
	nginxVersionTimeout = 5 * time.Second
)

var nginxVersionPattern = regexp.MustCompile(`nginx/([0-9][0-9A-Za-z.\-]*)`)

// nginxVersionCache keeps the last version nginx reported. A failed read is
// not kept, so the next caller tries again.
type nginxVersionCache struct {
	mu     sync.Mutex
	value  string
	readAt time.Time
}

// Version returns the version of the nginx running in the nginx container,
// such as "1.29.4", for the header next to NPG's own (#369).
func (m *Manager) Version(ctx context.Context) (string, error) {
	if m.skipTest {
		return "", fmt.Errorf("nginx is not managed here")
	}
	c := &m.version
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != "" && time.Since(c.readAt) < nginxVersionTTL {
		return c.value, nil
	}
	ctx, cancel := context.WithTimeout(ctx, nginxVersionTimeout)
	defer cancel()
	// nginx -v writes to stderr.
	out, err := exec.CommandContext(ctx, "docker", "exec", m.nginxContainer, "nginx", "-v").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nginx -v: %w", err)
	}
	v, err := parseNginxVersion(string(out))
	if err != nil {
		return "", err
	}
	c.value, c.readAt = v, time.Now()
	return v, nil
}

// parseNginxVersion takes the version out of `nginx -v` output:
// "nginx version: nginx/1.29.4".
func parseNginxVersion(out string) (string, error) {
	m := nginxVersionPattern.FindStringSubmatch(out)
	if m == nil {
		if len(out) > 80 {
			out = out[:80]
		}
		return "", fmt.Errorf("unexpected nginx -v output: %q", out)
	}
	return m[1], nil
}
