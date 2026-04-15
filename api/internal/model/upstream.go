package model

import "time"

// Upstream represents an upstream configuration for load balancing
type Upstream struct {
	ID                        string           `json:"id"`
	ProxyHostID               string           `json:"proxy_host_id"`
	Name                      string           `json:"name"`
	Scheme                    string           `json:"scheme"` // "http" or "https" - protocol used to reach upstream servers
	Servers                   []UpstreamServer `json:"servers"`
	LoadBalance               string           `json:"load_balance"`
	HealthCheckEnabled        bool             `json:"health_check_enabled"`
	HealthCheckInterval       int              `json:"health_check_interval"`
	HealthCheckTimeout        int              `json:"health_check_timeout"`
	HealthCheckPath           string           `json:"health_check_path"`
	HealthCheckExpectedStatus int              `json:"health_check_expected_status"`
	Keepalive                 int              `json:"keepalive"`
	IsHealthy                 bool             `json:"is_healthy"`
	LastCheckAt               *time.Time       `json:"last_check_at,omitempty"`
	CreatedAt                 time.Time        `json:"created_at"`
	UpdatedAt                 time.Time        `json:"updated_at"`
}

// UpstreamServer represents a single server in an upstream
type UpstreamServer struct {
	ID          string     `json:"id,omitempty"`
	UpstreamID  string     `json:"upstream_id,omitempty"`
	Address     string     `json:"address"`
	Port        int        `json:"port"`
	Weight      int        `json:"weight"`
	MaxFails    int        `json:"max_fails"`
	FailTimeout int        `json:"fail_timeout"`
	IsBackup    bool       `json:"is_backup"`
	IsDown      bool       `json:"is_down"`
	IsHealthy   bool       `json:"is_healthy"`
	LastCheckAt *time.Time `json:"last_check_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at,omitempty"`
}

// CreateUpstreamRequest is the request to create/update upstream config
type CreateUpstreamRequest struct {
	Name                      string                        `json:"name,omitempty"`
	Scheme                    string                        `json:"scheme,omitempty"` // "http" (default) or "https"
	Servers                   []CreateUpstreamServerRequest `json:"servers,omitempty"`
	LoadBalance               string                        `json:"load_balance,omitempty"`
	HealthCheckEnabled        *bool                         `json:"health_check_enabled,omitempty"`
	HealthCheckInterval       int                           `json:"health_check_interval,omitempty"`
	HealthCheckTimeout        int                           `json:"health_check_timeout,omitempty"`
	HealthCheckPath           string                        `json:"health_check_path,omitempty"`
	HealthCheckExpectedStatus int                           `json:"health_check_expected_status,omitempty"`
	Keepalive                 int                           `json:"keepalive,omitempty"`
}

// CreateUpstreamServerRequest is the request to add a server to upstream
type CreateUpstreamServerRequest struct {
	Address     string `json:"address"`
	Port        int    `json:"port,omitempty"`
	Weight      int    `json:"weight,omitempty"`
	MaxFails    int    `json:"max_fails,omitempty"`
	FailTimeout int    `json:"fail_timeout,omitempty"`
	IsBackup    bool   `json:"is_backup,omitempty"`
	IsDown      bool   `json:"is_down,omitempty"`
}

// UpstreamHealthStatus represents the health status of an upstream
type UpstreamHealthStatus struct {
	UpstreamID    string               `json:"upstream_id"`
	Name          string               `json:"name"`
	IsHealthy     bool                 `json:"is_healthy"`
	HealthyCount  int                  `json:"healthy_count"`
	UnhealthyCount int                 `json:"unhealthy_count"`
	LastCheckAt   *time.Time           `json:"last_check_at,omitempty"`
	Servers       []ServerHealthStatus `json:"servers"`
}

// ServerHealthStatus represents the health status of a single server
type ServerHealthStatus struct {
	Address     string     `json:"address"`
	Port        int        `json:"port"`
	IsHealthy   bool       `json:"is_healthy"`
	IsBackup    bool       `json:"is_backup"`
	IsDown      bool       `json:"is_down"`
	LastCheckAt *time.Time `json:"last_check_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	ResponseTime int64     `json:"response_time_ms,omitempty"`
}

// Valid load balancing methods
var ValidLoadBalanceMethods = []string{
	"round_robin",
	"least_conn",
	"ip_hash",
	"random",
}

// Valid upstream schemes
var ValidUpstreamSchemes = []string{"http", "https"}

// NormalizeUpstreamScheme returns "http" (default) or "https". Anything else falls back to "http".
func NormalizeUpstreamScheme(s string) string {
	if s == "https" {
		return "https"
	}
	return "http"
}
