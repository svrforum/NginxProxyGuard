package model

import "time"

// Raw log reclaim job states (raw_log_reclaim_job.status).
const (
	RawReclaimIdle    = "idle"
	RawReclaimRunning = "running"
	RawReclaimPaused  = "paused"
	RawReclaimDone    = "done"
	RawReclaimFailed  = "failed"
)

// Where the job is in the day it works on (LogRawReclaimChunkProgress.Step).
const (
	RawReclaimStepWaitingDisk = "waiting_disk" // the database disk is critical: emergency compression's turn
	RawReclaimStepWaitingLock = "waiting_lock" // another job is rewriting chunks
	RawReclaimStepNulling     = "nulling"      // removing the raw_log copies
	RawReclaimStepWaiting     = "waiting"      // for transactions older than the removal to end
	RawReclaimStepVacuum      = "vacuum"       // VACUUM FULL: the day's queries wait meanwhile
	RawReclaimStepPausing     = "pausing"      // the pause between days
)

// LogRawReclaimStatus is GET /system-settings/log-storage/raw-reclaim: the
// opt-in job that removes the raw_log copies of access and error lines kept
// inside old compressed log history, one day at a time. The verbatim lines
// stay in the raw log files for their own retention; WAF (ModSecurity) events
// keep theirs.
type LogRawReclaimStatus struct {
	// idle | running | paused | done | failed
	Status string `json:"status"`
	// false when this database cannot run the job (TimescaleDB missing, or its
	// catalog not as expected); UnsupportedReason says why.
	Supported         bool   `json:"supported"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`

	RequestedAt *time.Time `json:"requested_at,omitempty"`
	RequestedBy string     `json:"requested_by,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	MaxChunks   *int       `json:"max_chunks,omitempty"`
	// Set while an interrupted run waits to resume after an API restart.
	ResumeAt *time.Time `json:"resume_at,omitempty"`

	// Days the job has recorded — every day it found raw_log to remove in,
	// except unfinished ones retention has since dropped — and where they are.
	ChunksTotal   int `json:"chunks_total"`
	ChunksDone    int `json:"chunks_done"`
	ChunksPending int `json:"chunks_pending"`
	ChunksSkipped int `json:"chunks_skipped"`
	ChunksFailed  int `json:"chunks_failed"`

	// Sizes of the finished days' compressed data, before and after.
	BytesBefore    int64 `json:"bytes_before"`
	BytesAfter     int64 `json:"bytes_after"`
	ReclaimedBytes int64 `json:"reclaimed_bytes"`
	// raw_log bytes still held by the planned days that are not finished.
	RemainingRawBytes int64 `json:"remaining_raw_bytes"`

	// The live estimate, refreshed by ?estimate=1 at most every 10 minutes:
	// raw_log bytes of access/error lines in compressed days old enough to
	// process, and the WAF (ModSecurity) raw_log bytes that are kept.
	EstimatedReclaimableBytes *int64     `json:"estimated_reclaimable_bytes,omitempty"`
	ModSecRawBytes            *int64     `json:"modsec_raw_bytes,omitempty"`
	EstimateChunks            *int       `json:"estimate_chunks,omitempty"`
	EstimatedAt               *time.Time `json:"estimated_at,omitempty"`

	// The day being worked on; absent between runs and while planning.
	CurrentChunk *LogRawReclaimChunkProgress `json:"current_chunk,omitempty"`

	// Free space on the database's disk at the last measurement (absent when
	// unknown), and what the next day needs: twice its size without the
	// raw_log copies, plus 1 GiB.
	FreeBytes         *int64 `json:"free_bytes,omitempty"`
	RequiredFreeBytes int64  `json:"required_free_bytes"`

	LastError string `json:"last_error,omitempty"`
}

// LogRawReclaimChunkProgress is the day the job is on.
type LogRawReclaimChunkProgress struct {
	RangeStart time.Time `json:"range_start"`
	RangeEnd   time.Time `json:"range_end"`
	// waiting_disk | waiting_lock | nulling | waiting | vacuum | pausing
	Step  string    `json:"step"`
	Since time.Time `json:"since"`
}

// StartRawLogReclaimRequest is POST .../raw-reclaim/start. MaxChunks limits
// how many days this request works on; absent means all of them.
type StartRawLogReclaimRequest struct {
	MaxChunks *int `json:"max_chunks,omitempty"`
}
