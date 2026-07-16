package nginx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// cloudflaredTokenPath derives the token file location from the manager's
// config path (/etc/nginx/conf.d -> /etc/nginx/cloudflared/token). The api and
// nginx containers mount the same nginx_data volume at /etc/nginx, and the
// entrypoint supervisor in the nginx image watches exactly this path.
func (m *Manager) cloudflaredTokenPath() string {
	return filepath.Join(filepath.Dir(m.configPath), "cloudflared", "token")
}

// WriteCloudflaredToken persists the connector token atomically with 0600
// perms (0700 dir). The in-container supervisor picks up the mtime change —
// no reload, no docker exec.
func (m *Manager) WriteCloudflaredToken(token string) error {
	p := m.cloudflaredTokenPath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return fmt.Errorf("failed to create cloudflared dir: %w", err)
	}
	return m.writeFileAtomic(p, []byte(token+"\n"), 0600)
}

// RemoveCloudflaredToken deletes the token file (supervisor stops the connector).
func (m *Manager) RemoveCloudflaredToken() error {
	err := os.Remove(m.cloudflaredTokenPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// CloudflaredReady queries the connector's metrics /ready endpoint inside the
// nginx container (bound to loopback — not reachable from the api container
// directly under host networking, hence docker exec like nginx -t). The port
// comes from CLOUDFLARED_METRICS_PORT (default 20241) and must match the same
// env on the nginx container, whose entrypoint supervisor passes it to
// cloudflared --metrics. Returns the number of active edge connections.
func (m *Manager) CloudflaredReady(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	port := os.Getenv("CLOUDFLARED_METRICS_PORT")
	if port == "" {
		port = "20241"
	}
	cmd := exec.CommandContext(ctx, "docker", "exec", m.nginxContainer,
		"curl", "-fsS", "http://127.0.0.1:"+port+"/ready")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("cloudflared ready probe failed: %w", err)
	}
	var body struct {
		ReadyConnections int `json:"readyConnections"`
	}
	if err := json.Unmarshal(out, &body); err != nil {
		return 0, fmt.Errorf("cloudflared ready probe: bad response: %w", err)
	}
	return body.ReadyConnections, nil
}
