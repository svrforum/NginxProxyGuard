package nginx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// nginxCLI abstracts the two docker exec calls the manager needs so
// tests can substitute a fake implementation without touching docker.
type nginxCLI interface {
	Test(ctx context.Context) error
	Reload(ctx context.Context) error
}

// dockerNginxCLI runs nginx commands via docker exec against the configured container.
type dockerNginxCLI struct {
	containerName string
}

func newDockerNginxCLI(containerName string) *dockerNginxCLI {
	return &dockerNginxCLI{containerName: containerName}
}

// Test runs `nginx -t` inside the container. Returns a non-nil error when the
// configuration is invalid or the exec itself fails.
func (d *dockerNginxCLI) Test(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", d.containerName, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// Reload runs `nginx -s reload` inside the container. A nil error means the
// reload signal was delivered (post-signal worker health is verified separately).
func (d *dockerNginxCLI) Reload(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", d.containerName, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -s reload failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
