package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
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

// DockerStatsService provides Docker container statistics
type DockerStatsService struct{}

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
	Containers     []ContainerStats `json:"containers"`
	Volumes        []VolumeStats    `json:"volumes"`
	TotalCPU       float64          `json:"total_cpu_percent"`
	TotalMemory    int64            `json:"total_memory_usage"`
	TotalMemLimit  int64            `json:"total_memory_limit"`
	TotalVolumeSize int64           `json:"total_volume_size"`
	ContainerCount int              `json:"container_count"`
	HealthyCount   int              `json:"healthy_count"`
	UpdatedAt      time.Time        `json:"updated_at"`
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

// GetVolumeStats retrieves Docker volume statistics for npg volumes
func (s *DockerStatsService) GetVolumeStats(ctx context.Context) ([]VolumeStats, error) {
	// Get list of npg_ volumes
	cmd := exec.CommandContext(ctx, "docker", "volume", "ls", "--filter", "name=npg_", "--format", "{{.Name}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	names := strings.Split(strings.TrimSpace(string(output)), "\n")

	// Get all volume sizes in a single docker command (no container creation)
	volumeSizes, sizeErr := s.getVolumeSizesFromSystemDF(ctx)
	if sizeErr != nil {
		// Graceful degradation: continue without sizes if docker system df fails
		volumeSizes = make(map[string]int64)
	}

	var volumes []VolumeStats
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

	return volumes, nil
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

// GetStatsSummary returns a summary of all container stats
func (s *DockerStatsService) GetStatsSummary(ctx context.Context) (*DockerStatsSummary, error) {
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
