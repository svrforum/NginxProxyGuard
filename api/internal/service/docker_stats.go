package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ContainerStats represents Docker container resource statistics
type ContainerStats struct {
	ContainerID   string  `json:"container_id"`
	ContainerName string  `json:"container_name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsage   int64   `json:"memory_usage"`
	MemoryLimit   int64   `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	NetI          int64   `json:"net_i"`
	NetO          int64   `json:"net_o"`
	BlockI        int64   `json:"block_i"`
	BlockO        int64   `json:"block_o"`
	PIDs          int     `json:"pids"`
	Status        string  `json:"status"`
}

const (
	// dockerStatsSummaryTTL bounds how often `docker stats --no-stream` (which
	// blocks ~2s while dockerd samples CPU for every container on the host)
	// can run. The dashboard polls every 60s; this mainly collapses multiple
	// open tabs and rapid refreshes into one sample.
	dockerStatsSummaryTTL = 15 * time.Second
	// dockerVolumeStatsTTL bounds `docker system df -v`, which makes dockerd
	// walk the disk usage of ALL images/containers/volumes on the host (the
	// npg_ filter only applies after dockerd computed everything). Volume
	// sizes change slowly, so refresh them on a much longer cadence.
	dockerVolumeStatsTTL = 5 * time.Minute
)

// DockerStatsService provides Docker container statistics
type DockerStatsService struct {
	mu sync.Mutex // guards the cached results below
	sf singleflight.Group

	cachedSummary    *DockerStatsSummary
	summaryExpiresAt time.Time

	cachedVolumes    []VolumeStats
	volumesExpiresAt time.Time
}

// NewDockerStatsService creates a new DockerStatsService
func NewDockerStatsService() *DockerStatsService {
	return &DockerStatsService{}
}

// GetContainerStats retrieves resource statistics for nginx-guard containers
func (s *DockerStatsService) GetContainerStats(ctx context.Context) ([]ContainerStats, error) {
	// Get container stats using docker stats command
	cmd := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format",
		`{"container_id":"{{.ID}}","container_name":"{{.Name}}","cpu":"{{.CPUPerc}}","mem_usage":"{{.MemUsage}}","mem_perc":"{{.MemPerc}}","net":"{{.NetIO}}","block":"{{.BlockIO}}","pids":"{{.PIDs}}"}`)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker stats: %w", err)
	}

	var stats []ContainerStats
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var rawStats struct {
			ContainerID   string `json:"container_id"`
			ContainerName string `json:"container_name"`
			CPU           string `json:"cpu"`
			MemUsage      string `json:"mem_usage"`
			MemPerc       string `json:"mem_perc"`
			Net           string `json:"net"`
			Block         string `json:"block"`
			PIDs          string `json:"pids"`
		}

		if err := json.Unmarshal([]byte(line), &rawStats); err != nil {
			continue
		}

		// Only include npg containers
		if !strings.Contains(rawStats.ContainerName, "npg") {
			continue
		}

		stat := ContainerStats{
			ContainerID:   rawStats.ContainerID,
			ContainerName: rawStats.ContainerName,
			Status:        "running",
		}

		// Parse CPU percentage
		stat.CPUPercent = parsePercentage(rawStats.CPU)

		// Parse memory usage and limit
		stat.MemoryUsage, stat.MemoryLimit = parseMemoryUsage(rawStats.MemUsage)
		stat.MemoryPercent = parsePercentage(rawStats.MemPerc)

		// Parse network I/O
		stat.NetI, stat.NetO = parseIOPair(rawStats.Net)

		// Parse block I/O
		stat.BlockI, stat.BlockO = parseIOPair(rawStats.Block)

		// Parse PIDs
		fmt.Sscanf(rawStats.PIDs, "%d", &stat.PIDs)

		stats = append(stats, stat)
	}

	return stats, nil
}

// GetContainerStatus retrieves container status information
func (s *DockerStatsService) GetContainerStatus(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=npg",
		"--format", `{"name":"{{.Names}}","status":"{{.Status}}","state":"{{.State}}"}`)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get container status: %w", err)
	}

	status := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var info struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			State  string `json:"state"`
		}

		if err := json.Unmarshal([]byte(line), &info); err != nil {
			continue
		}

		status[info.Name] = info.State
	}

	return status, nil
}

// parsePercentage parses a percentage string like "0.50%" into a float64
func parsePercentage(s string) float64 {
	s = strings.TrimSuffix(s, "%")
	var val float64
	fmt.Sscanf(s, "%f", &val)
	return val
}

// parseMemoryUsage parses memory usage string like "50MiB / 1GiB" into bytes
func parseMemoryUsage(s string) (usage int64, limit int64) {
	parts := strings.Split(s, " / ")
	if len(parts) == 2 {
		usage = parseSizeToBytes(strings.TrimSpace(parts[0]))
		limit = parseSizeToBytes(strings.TrimSpace(parts[1]))
	}
	return
}

// parseIOPair parses I/O string like "100MB / 50MB" into bytes
func parseIOPair(s string) (in int64, out int64) {
	parts := strings.Split(s, " / ")
	if len(parts) == 2 {
		in = parseSizeToBytes(strings.TrimSpace(parts[0]))
		out = parseSizeToBytes(strings.TrimSpace(parts[1]))
	}
	return
}

// parseSizeToBytes parses size strings like "50MiB", "1.5GiB", "100kB" to bytes
func parseSizeToBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "0B" || s == "" {
		return 0
	}

	var val float64
	var unit string

	// Try different formats
	if n, _ := fmt.Sscanf(s, "%f%s", &val, &unit); n == 2 {
		unit = strings.ToUpper(unit)
		switch {
		case strings.HasPrefix(unit, "KIB") || strings.HasPrefix(unit, "KB"):
			return int64(val * 1024)
		case strings.HasPrefix(unit, "MIB") || strings.HasPrefix(unit, "MB"):
			return int64(val * 1024 * 1024)
		case strings.HasPrefix(unit, "GIB") || strings.HasPrefix(unit, "GB"):
			return int64(val * 1024 * 1024 * 1024)
		case strings.HasPrefix(unit, "TIB") || strings.HasPrefix(unit, "TB"):
			return int64(val * 1024 * 1024 * 1024 * 1024)
		case strings.HasPrefix(unit, "B"):
			return int64(val)
		}
	}

	return 0
}

// VolumeStats represents Docker volume statistics
type VolumeStats struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
}

// Summary returns a summary of container resource usage
type DockerStatsSummary struct {
	Containers      []ContainerStats `json:"containers"`
	Volumes         []VolumeStats    `json:"volumes"`
	TotalCPU        float64          `json:"total_cpu_percent"`
	TotalMemory     int64            `json:"total_memory_usage"`
	TotalMemLimit   int64            `json:"total_memory_limit"`
	TotalVolumeSize int64            `json:"total_volume_size"`
	ContainerCount  int              `json:"container_count"`
	HealthyCount    int              `json:"healthy_count"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// getVolumeSizesFromSystemDF retrieves all volume sizes in a single docker command
// This replaces the inefficient per-volume container creation approach
func (s *DockerStatsService) getVolumeSizesFromSystemDF(ctx context.Context) (map[string]int64, error) {
	cmd := exec.CommandContext(ctx, "docker", "system", "df", "-v", "--format", "{{json .Volumes}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker system df: %w", err)
	}

	var volumeInfos []struct {
		Name string `json:"Name"`
		Size string `json:"Size"`
	}

	if err := json.Unmarshal(output, &volumeInfos); err != nil {
		return nil, fmt.Errorf("failed to parse volumes JSON: %w", err)
	}

	sizes := make(map[string]int64)
	for _, vol := range volumeInfos {
		if strings.HasPrefix(vol.Name, "npg_") {
			sizes[vol.Name] = parseSizeToBytes(vol.Size)
		}
	}

	return sizes, nil
}

// GetVolumeStats retrieves Docker volume statistics for npg volumes. Results
// are cached (dockerVolumeStatsTTL) and recomputation is singleflight-protected
// because the underlying `docker system df -v` is a host-wide dockerd disk walk
// that the dashboard would otherwise trigger on every poll.
func (s *DockerStatsService) GetVolumeStats(ctx context.Context) ([]VolumeStats, error) {
	s.mu.Lock()
	if !s.volumesExpiresAt.IsZero() && time.Now().Before(s.volumesExpiresAt) {
		volumes := s.cachedVolumes
		s.mu.Unlock()
		return volumes, nil
	}
	s.mu.Unlock()

	v, err, _ := s.sf.Do("volume_stats", func() (interface{}, error) {
		// Detached context: the result is shared by all singleflight waiters,
		// so one client disconnect must not cancel it. The timeout keeps a
		// wedged dockerd from pinning the singleflight slot forever.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()

		volumes, sizesOK, err := s.computeVolumeStats(cctx)
		if err != nil {
			return nil, err
		}
		ttl := dockerVolumeStatsTTL
		if !sizesOK {
			// docker system df failed (sizes missing): retry sooner so the
			// degraded entry doesn't stick for the full long TTL.
			ttl = dockerStatsSummaryTTL
		}
		s.mu.Lock()
		s.cachedVolumes = volumes
		s.volumesExpiresAt = time.Now().Add(ttl)
		s.mu.Unlock()
		return volumes, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]VolumeStats), nil
}

// computeVolumeStats does the actual docker CLI work for GetVolumeStats.
// sizesOK reports whether volume sizes were obtained from docker system df.
func (s *DockerStatsService) computeVolumeStats(ctx context.Context) (volumes []VolumeStats, sizesOK bool, err error) {
	// Get list of npg_ volumes
	cmd := exec.CommandContext(ctx, "docker", "volume", "ls", "--filter", "name=npg_", "--format", "{{.Name}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, false, fmt.Errorf("failed to list volumes: %w", err)
	}

	names := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Get all volume sizes in a single docker command (no container creation)
	volumeSizes, sizeErr := s.getVolumeSizesFromSystemDF(ctx)
	if sizeErr != nil {
		// Graceful degradation: continue without sizes if docker system df fails
		volumeSizes = make(map[string]int64)
	}

	for _, name := range names {
		if name == "" {
			continue
		}

		vol := VolumeStats{
			Name:   name,
			Driver: "local",
		}

		// Use pre-fetched size from docker system df
		if size, ok := volumeSizes[name]; ok {
			vol.Size = size
			vol.SizeHuman = formatBytes(size)
		}

		volumes = append(volumes, vol)
	}

	return volumes, sizeErr == nil, nil
}

// formatBytes formats bytes to human readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetStatsSummary returns a summary of all container stats. Results are
// cached (dockerStatsSummaryTTL) and recomputation is singleflight-protected:
// the underlying `docker stats --no-stream` blocks ~2s per run, and the
// dashboard polls this endpoint every 60s per open tab.
func (s *DockerStatsService) GetStatsSummary(ctx context.Context) (*DockerStatsSummary, error) {
	s.mu.Lock()
	if s.cachedSummary != nil && time.Now().Before(s.summaryExpiresAt) {
		summary := s.cachedSummary
		s.mu.Unlock()
		return summary, nil
	}
	s.mu.Unlock()

	v, err, _ := s.sf.Do("stats_summary", func() (interface{}, error) {
		// Detached context: the result is shared by all singleflight waiters
		// (see GetVolumeStats for the rationale).
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()

		summary, err := s.computeStatsSummary(cctx)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.cachedSummary = summary
		s.summaryExpiresAt = time.Now().Add(dockerStatsSummaryTTL)
		s.mu.Unlock()
		return summary, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*DockerStatsSummary), nil
}

// computeStatsSummary does the actual docker CLI work for GetStatsSummary.
func (s *DockerStatsService) computeStatsSummary(ctx context.Context) (*DockerStatsSummary, error) {
	stats, err := s.GetContainerStats(ctx)
	if err != nil {
		return nil, err
	}

	status, _ := s.GetContainerStatus(ctx)
	volumes, _ := s.GetVolumeStats(ctx)

	summary := &DockerStatsSummary{
		Containers:     stats,
		Volumes:        volumes,
		ContainerCount: len(stats),
		UpdatedAt:      time.Now(),
	}

	for i := range stats {
		summary.TotalCPU += stats[i].CPUPercent
		summary.TotalMemory += stats[i].MemoryUsage
		summary.TotalMemLimit += stats[i].MemoryLimit

		// Update status from docker ps
		if state, ok := status[stats[i].ContainerName]; ok {
			stats[i].Status = state
			if state == "running" {
				summary.HealthyCount++
			}
		}
	}

	// Calculate total volume size
	for _, vol := range volumes {
		summary.TotalVolumeSize += vol.Size
	}

	return summary, nil
}

// DockerContainerInfo represents a Docker container with its network information
type DockerContainerInfo struct {
	Name     string                   `json:"name"`
	Image    string                   `json:"image"`
	State    string                   `json:"state"`
	Networks []DockerContainerNetwork `json:"networks"`
	Ports    []DockerContainerPort    `json:"ports"`
}

// DockerContainerNetwork represents a container's network attachment
type DockerContainerNetwork struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

// DockerContainerPort represents a container's exposed port
type DockerContainerPort struct {
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// isHiddenContainer reports whether a container is excluded from the proxy-host
// docker picker. NPG's own infra containers are hidden, EXCEPT the admin UI
// (npg-ui), which users legitimately proxy externally (e.g. to expose the UI
// behind a domain). (#155)
func isHiddenContainer(name string) bool {
	if name == "" {
		return true
	}
	if name == "npg-ui" || name == "npg_ui" {
		return false
	}
	return strings.HasPrefix(name, "npg-") || strings.HasPrefix(name, "npg_")
}

// ListContainersWithNetworks returns all running containers with their network IPs,
// excluding NPG infra containers (except the admin UI, npg-ui). This is used by the
// UI to help users select Docker containers as proxy targets when nginx runs in
// host network mode.
func (s *DockerStatsService) ListContainersWithNetworks(ctx context.Context) ([]DockerContainerInfo, error) {
	// Get all running containers (NPG infra containers are filtered by isHiddenContainer)
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", `{{.Names}}`)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var names []string
	for _, name := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		name = strings.TrimSpace(name)
		if isHiddenContainer(name) {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, nil
	}

	infos, err := s.inspectContainers(ctx, names)
	if err != nil {
		return nil, err
	}

	var containers []DockerContainerInfo
	for i := range infos {
		// Only include containers that have at least one network with an IP
		hasIP := false
		for _, net := range infos[i].Networks {
			if net.IPAddress != "" {
				hasIP = true
				break
			}
		}
		if hasIP {
			containers = append(containers, infos[i])
		}
	}

	sortContainers(containers)
	return containers, nil
}

// pickContainerIP returns a network IP for the container whose name matches.
// When network is non-empty, returns the IP of the network whose Name matches
// exactly (case-sensitive); errors if no such network is attached — this is the
// network-aware path used after Issue #151 so multi-network containers don't
// get reconciled to a wrong-network IP. When network is empty, falls back to
// the legacy behavior of returning the first non-empty network IP (still used
// for create/update flexibility when the caller has not stored a network).
// Pure, for testability. (#150, #151)
func pickContainerIP(containers []DockerContainerInfo, name string, network string) (string, error) {
	for _, c := range containers {
		if c.Name != name {
			continue
		}
		if network != "" {
			for _, n := range c.Networks {
				if n.Name == network {
					if n.IPAddress == "" {
						return "", fmt.Errorf("container %q on network %q has no IP", name, network)
					}
					return n.IPAddress, nil
				}
			}
			return "", fmt.Errorf("container %q is not attached to network %q", name, network)
		}
		for _, n := range c.Networks {
			if n.IPAddress != "" {
				return n.IPAddress, nil
			}
		}
		return "", fmt.Errorf("container %q has no network IP", name)
	}
	return "", fmt.Errorf("container %q not found or not running", name)
}

// ResolveContainerIP resolves a running container name to its current network IP
// via docker.sock. When network is non-empty, resolution is pinned to that
// specific docker network (Issue #151); when empty, the first non-empty IP is
// returned for backwards-compatibility with callers that have no stored
// network. (#150, #151)
func (s *DockerStatsService) ResolveContainerIP(ctx context.Context, name string, network string) (string, error) {
	containers, err := s.ListContainersWithNetworks(ctx)
	if err != nil {
		return "", err
	}
	return pickContainerIP(containers, name, network)
}

// ResolveContainerIPFromList resolves a container name to its current network
// IP against an already-fetched container snapshot, with the same #150/#151
// network-pinning semantics as ResolveContainerIP (see pickContainerIP). Used
// by the container reconcile scheduler so one docker snapshot per tick serves
// every container-backed host instead of re-listing per host.
func (s *DockerStatsService) ResolveContainerIPFromList(containers []DockerContainerInfo, name string, network string) (string, error) {
	return pickContainerIP(containers, name, network)
}

// sortContainerInfo orders a container's networks (by name) and ports (by port
// number, then protocol) deterministically. Docker inspect returns these from
// Go maps, so without this the UI reshuffles them on every refresh. (Issue #153)
func sortContainerInfo(info *DockerContainerInfo) {
	sort.Slice(info.Networks, func(i, j int) bool {
		return info.Networks[i].Name < info.Networks[j].Name
	})
	sort.Slice(info.Ports, func(i, j int) bool {
		if info.Ports[i].ContainerPort != info.Ports[j].ContainerPort {
			return info.Ports[i].ContainerPort < info.Ports[j].ContainerPort
		}
		return info.Ports[i].Protocol < info.Ports[j].Protocol
	})
}

// sortContainers orders containers by name for a stable picker list. (Issue #153)
func sortContainers(containers []DockerContainerInfo) {
	sort.Slice(containers, func(i, j int) bool {
		return containers[i].Name < containers[j].Name
	})
}

// inspectContainers gets detailed network info for the given containers in a
// SINGLE `docker inspect` exec (docker inspect accepts multiple names). The
// previous one-exec-per-container loop multiplied subprocess forks by the
// running-container count for every caller — notably the 30s container
// reconcile tick. A non-zero exit with partial output (a container vanished
// between `docker ps` and the inspect) degrades to skipping the missing one,
// matching the old per-container skip-on-error behavior.
func (s *DockerStatsService) inspectContainers(ctx context.Context, names []string) ([]DockerContainerInfo, error) {
	args := append([]string{"inspect", "--format",
		`{"name":"{{.Name}}","image":"{{.Config.Image}}","state":"{{.State.Status}}","networks":{{json .NetworkSettings.Networks}},"ports":{{json .Config.ExposedPorts}}}`},
		names...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	trimmed := strings.TrimSpace(string(output))
	if err != nil && trimmed == "" {
		return nil, fmt.Errorf("failed to inspect containers: %w", err)
	}

	var infos []DockerContainerInfo
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		info, err := parseInspectLine(line)
		if err != nil {
			continue
		}
		infos = append(infos, *info)
	}
	return infos, nil
}

// parseInspectLine parses one formatted line of `docker inspect` output into
// a DockerContainerInfo.
func parseInspectLine(line string) (*DockerContainerInfo, error) {
	var raw struct {
		Name     string                     `json:"name"`
		Image    string                     `json:"image"`
		State    string                     `json:"state"`
		Networks map[string]json.RawMessage `json:"networks"`
		Ports    map[string]json.RawMessage `json:"ports"`
	}

	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse inspect output: %w", err)
	}

	info := &DockerContainerInfo{
		Name:     strings.TrimPrefix(raw.Name, "/"), // docker inspect reports "/name"
		Image:    raw.Image,
		State:    raw.State,
		Networks: []DockerContainerNetwork{},
		Ports:    []DockerContainerPort{},
	}

	// Parse networks
	for netName, netData := range raw.Networks {
		var netInfo struct {
			IPAddress string `json:"IPAddress"`
		}
		if err := json.Unmarshal(netData, &netInfo); err != nil {
			continue
		}
		if netInfo.IPAddress != "" {
			info.Networks = append(info.Networks, DockerContainerNetwork{
				Name:      netName,
				IPAddress: netInfo.IPAddress,
			})
		}
	}

	// Parse exposed ports (e.g., "8080/tcp": {})
	for portProto := range raw.Ports {
		parts := strings.SplitN(portProto, "/", 2)
		if len(parts) == 2 {
			var port int
			if _, err := fmt.Sscanf(parts[0], "%d", &port); err == nil {
				proto := parts[1]
				if proto == "" {
					proto = "tcp"
				}
				info.Ports = append(info.Ports, DockerContainerPort{
					ContainerPort: port,
					Protocol:      proto,
				})
			}
		}
	}

	sortContainerInfo(info)

	return info, nil
}
