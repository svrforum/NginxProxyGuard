package model

import "time"

// StorageStatus is DiskGuard's picture of the filesystems NPG writes to
// (D1-D4). It is attached live to GET /dashboard and is never cached with the
// rest of the dashboard summary: a stale "disk ok" is the one number on that
// page that must not lag.
//
// GET /health/detailed gets the reduced StorageHealth instead (see Health).
type StorageStatus struct {
	// Level is the worst filesystem's level: ok | low | critical.
	Level       string            `json:"level"`
	Thresholds  StorageThresholds `json:"thresholds"`
	Filesystems []FilesystemUsage `json:"filesystems"` // fullest first
	// Stalled lists roles whose filesystem did not answer in time — a hung
	// network mount. They have no numbers and no entry in Filesystems.
	Stalled  []StalledFilesystem `json:"stalled,omitempty"`
	Database DatabaseDiskInfo    `json:"database"`
	// Emergency is D3, the early compression of closed log chunks when the
	// database disk is critical.
	Emergency  *EmergencyCompressionStatus `json:"emergency,omitempty"`
	MeasuredAt time.Time                   `json:"measured_at"`
}

// EmergencyCompressionStatus reports D3: compressing closed log chunks early
// when the database disk passes the critical line.
type EmergencyCompressionStatus struct {
	Mode  string `json:"mode"`  // on | off | dryrun (NPG_DISK_EMERGENCY_COMPRESS)
	State string `json:"state"` // idle | running | done | blocked
	// Reason explains done or blocked: nothing_to_compress, dry_run,
	// insufficient_space, policy_running, another_pass_running, chunks_busy,
	// db_disk_unmeasured, compress_failed, error.
	Reason      string     `json:"reason,omitempty"`
	ChunksDone  int        `json:"chunks_done"`
	ChunksTotal int        `json:"chunks_total"`
	FreedBytes  int64      `json:"freed_bytes"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

type StorageThresholds struct {
	WarnPercent     float64 `json:"warn_percent"`
	CriticalPercent float64 `json:"critical_percent"`
	RecoverPercent  float64 `json:"recover_percent"`
}

// FilesystemUsage is one physical filesystem. Several roles share one when, as
// on a default install, every Docker volume lives on the same disk.
type FilesystemUsage struct {
	// Key is the most important role on the filesystem ("db" first). It is the
	// notification subject, so it must stay stable across restarts.
	Key   string   `json:"key"`
	Roles []string `json:"roles"`
	// Path names the primary role's location: "npg-db:/var/lib/postgresql/data"
	// for the database, a path inside the API container otherwise.
	Path   string `json:"path"`
	Source string `json:"source"` // statfs | docker_exec | docker_exec_df
	// Byte counts follow df: Used excludes reserved blocks and UsedPercent is
	// used/(used+avail), which is what a non-root writer such as Postgres sees.
	TotalBytes        uint64    `json:"total_bytes"`
	UsedBytes         uint64    `json:"used_bytes"`
	AvailBytes        uint64    `json:"avail_bytes"`
	UsedPercent       float64   `json:"used_percent"`
	Level             string    `json:"level"`
	GrowthPerDayBytes *int64    `json:"growth_per_day_bytes,omitempty"`
	DaysToFull        *float64  `json:"days_to_full,omitempty"`
	MeasuredAt        time.Time `json:"measured_at"`
}

// StalledFilesystem is a role whose filesystem stopped answering statfs.
type StalledFilesystem struct {
	Role  string    `json:"role"`
	Path  string    `json:"path"`
	Since time.Time `json:"since"`
}

// DatabaseDiskInfo says whether the database's own disk could be measured, and
// if not, why — the case where an operator has to act (set NPG_DB_CONTAINER).
type DatabaseDiskInfo struct {
	Measured  bool   `json:"measured"`
	Container string `json:"container,omitempty"`
	DataDir   string `json:"data_dir,omitempty"`
	// Reason is a code: db_container_not_found, db_external, db_exec_failed or
	// docker_unavailable. With Measured true and db_exec_failed, the container
	// could not be asked but a volume verified to share its disk answered.
	Reason string `json:"reason,omitempty"`
}

// StorageHealth is the part of StorageStatus that GET /health/detailed shows.
// That route is in PublicRoutes — any session, and an API token of any scope,
// reads it — so it carries levels, percentages, byte counts and codes only: no
// container name, data directory or mount path. Those stay in GET /dashboard,
// which needs the dashboard permission.
type StorageHealth struct {
	Level       string             `json:"level"`
	Thresholds  StorageThresholds  `json:"thresholds"`
	Filesystems []FilesystemHealth `json:"filesystems"`
	// StalledRoles are the roles of StorageStatus.Stalled, without their paths.
	StalledRoles []string                    `json:"stalled_roles,omitempty"`
	Database     DatabaseDiskHealth          `json:"database"`
	Emergency    *EmergencyCompressionStatus `json:"emergency,omitempty"`
	MeasuredAt   time.Time                   `json:"measured_at"`
}

// FilesystemHealth is FilesystemUsage without its path and source.
type FilesystemHealth struct {
	Key               string    `json:"key"`
	Roles             []string  `json:"roles"`
	Level             string    `json:"level"`
	UsedPercent       float64   `json:"used_percent"`
	TotalBytes        uint64    `json:"total_bytes"`
	UsedBytes         uint64    `json:"used_bytes"`
	AvailBytes        uint64    `json:"avail_bytes"`
	GrowthPerDayBytes *int64    `json:"growth_per_day_bytes,omitempty"`
	DaysToFull        *float64  `json:"days_to_full,omitempty"`
	MeasuredAt        time.Time `json:"measured_at"`
}

// DatabaseDiskHealth is DatabaseDiskInfo without the container and directory.
type DatabaseDiskHealth struct {
	Measured bool   `json:"measured"`
	Reason   string `json:"reason,omitempty"`
}

// Health is the /health/detailed view of s. nil stays nil (no measurement yet,
// or the guard is disabled).
func (s *StorageStatus) Health() *StorageHealth {
	if s == nil {
		return nil
	}
	h := &StorageHealth{
		Level:       s.Level,
		Thresholds:  s.Thresholds,
		Filesystems: make([]FilesystemHealth, 0, len(s.Filesystems)),
		Database:    DatabaseDiskHealth{Measured: s.Database.Measured, Reason: s.Database.Reason},
		Emergency:   s.Emergency,
		MeasuredAt:  s.MeasuredAt,
	}
	for _, f := range s.Filesystems {
		h.Filesystems = append(h.Filesystems, FilesystemHealth{
			Key: f.Key, Roles: f.Roles, Level: f.Level, UsedPercent: f.UsedPercent,
			TotalBytes: f.TotalBytes, UsedBytes: f.UsedBytes, AvailBytes: f.AvailBytes,
			GrowthPerDayBytes: f.GrowthPerDayBytes, DaysToFull: f.DaysToFull, MeasuredAt: f.MeasuredAt,
		})
	}
	for _, st := range s.Stalled {
		h.StalledRoles = append(h.StalledRoles, st.Role)
	}
	return h
}
