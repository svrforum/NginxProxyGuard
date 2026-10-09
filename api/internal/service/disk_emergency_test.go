package service

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

type fakeEmergencyRepo struct {
	mu         sync.Mutex
	cands      []repository.ChunkCandidate
	ratios     map[string]float64
	running    bool
	locked     bool
	errFor     map[string]error
	disk       *FSUsage // avail grows by 90% of each compressed chunk
	compressed []string
	onCompress func(name string)
}

func (f *fakeEmergencyRepo) CompressionCandidates(context.Context, int64) ([]repository.ChunkCandidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []repository.ChunkCandidate
	for _, c := range f.cands {
		done := false
		for _, n := range f.compressed {
			done = done || n == c.Name
		}
		if !done {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fakeEmergencyRepo) CompressionRatios(context.Context) (map[string]float64, error) {
	return f.ratios, nil
}
func (f *fakeEmergencyRepo) CompressionPolicyRunning(context.Context) (bool, error) {
	return f.running, nil
}
func (f *fakeEmergencyRepo) WithMaintenanceLock(ctx context.Context, fn func(context.Context, repository.ChunkCompressor) error) (bool, error) {
	if f.locked {
		return false, nil
	}
	return true, fn(ctx, f)
}
func (f *fakeEmergencyRepo) CompressChunk(_ context.Context, _, name string) error {
	if f.onCompress != nil {
		f.onCompress(name)
	}
	if err := f.errFor[name]; err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cands {
		if c.Name == name {
			f.disk.Avail += uint64(float64(c.Bytes) * 0.9)
			f.disk.Used -= uint64(float64(c.Bytes) * 0.9)
		}
	}
	f.compressed = append(f.compressed, name)
	return nil
}

func (f *fakeEmergencyRepo) compressedNames() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.compressed, ",")
}

func newTestEmergency(repo *fakeEmergencyRepo, mode EmergencyMode) *EmergencyCompressor {
	e := NewEmergencyCompressor(context.Background(), repo, func(context.Context) (*FSUsage, error) {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		d := *repo.disk
		d.UsedPercent = float64(d.Used) / float64(d.Used+d.Avail) * 100
		return &d, nil
	}, mode)
	e.sleep = func(context.Context, time.Duration) {}
	return e
}

func runEmergencyPass(e *EmergencyCompressor, repo *fakeEmergencyRepo) model.EmergencyCompressionStatus {
	e.TriggerAsync(*repo.disk)
	e.Wait()
	return e.Status()
}

const diskGiB = int64(1) << 30

func TestEmergencySmallestFirstWithSpaceCheck(t *testing.T) {
	// 188 GB disk, 2 GB free: the 1 GB chunk fits; after it the 8 GB one still
	// needs ~2.7 GB plus the 0.94 GB reserve, so it is skipped, not attempted.
	repo := &fakeEmergencyRepo{
		cands: []repository.ChunkCandidate{
			{Hypertable: "logs_partitioned", Schema: "_timescaledb_internal", Name: "big", Bytes: 8 * diskGiB},
			{Hypertable: "logs_partitioned", Schema: "_timescaledb_internal", Name: "small", Bytes: 1 * diskGiB},
		},
		ratios: map[string]float64{"logs_partitioned": 9},
		disk:   &FSUsage{Total: uint64(188 * diskGiB), Used: uint64(186 * diskGiB), Avail: uint64(2 * diskGiB)},
	}
	st := runEmergencyPass(newTestEmergency(repo, EmergencyOn), repo)
	if got := repo.compressedNames(); got != "small" {
		t.Fatalf("compressed %v; want only the small chunk (8 GB needs ~2.7 GB + reserve)", got)
	}
	if st.State != "done" || st.ChunksDone != 1 || st.ChunksTotal != 2 || st.FreedBytes <= 0 {
		t.Fatalf("status = %#v", st)
	}
}

func TestEmergencyStopsOnDiskFullAndSkipsLockedChunk(t *testing.T) {
	repo := &fakeEmergencyRepo{
		cands: []repository.ChunkCandidate{
			{Hypertable: "logs_partitioned", Schema: "s", Name: "a", Bytes: 100 << 20},
			{Hypertable: "logs_partitioned", Schema: "s", Name: "b", Bytes: 200 << 20},
			{Hypertable: "logs_partitioned", Schema: "s", Name: "c", Bytes: 300 << 20},
		},
		errFor: map[string]error{"a": &pq.Error{Code: "55P03"}, "b": &pq.Error{Code: "53100"}},
		disk:   &FSUsage{Total: uint64(100 * diskGiB), Used: uint64(90 * diskGiB), Avail: uint64(10 * diskGiB)},
	}
	var tried []string
	repo.onCompress = func(name string) { tried = append(tried, name) }
	st := runEmergencyPass(newTestEmergency(repo, EmergencyOn), repo)
	if repo.compressedNames() != "" || st.State != "blocked" || st.Reason != "insufficient_space" {
		t.Fatalf("compressed %v, status %#v", repo.compressedNames(), st)
	}
	if strings.Join(tried, ",") != "a,b" {
		t.Fatalf("tried %v; a disk-full error must stop the pass", tried)
	}
}

// A pass whose chunks were all locked by another job did not run out of room,
// and must not say so; it retries in a minute.
func TestEmergencyLockedChunksAreBusyNotFull(t *testing.T) {
	repo := &fakeEmergencyRepo{
		cands:  []repository.ChunkCandidate{{Hypertable: "h", Schema: "s", Name: "a", Bytes: 100 << 20}},
		errFor: map[string]error{"a": &pq.Error{Code: "55P03"}},
		disk:   &FSUsage{Total: uint64(100 * diskGiB), Used: uint64(91 * diskGiB), Avail: uint64(9 * diskGiB)},
	}
	e := newTestEmergency(repo, EmergencyOn)
	st := runEmergencyPass(e, repo)
	if st.State != "blocked" || st.Reason != "chunks_busy" || e.wait != emergencyRetrySoon {
		t.Fatalf("status %#v wait %v", st, e.wait)
	}
}

func TestEmergencyDefersToPolicyAndOtherPasses(t *testing.T) {
	repo := &fakeEmergencyRepo{running: true, disk: &FSUsage{Total: 100, Used: 95, Avail: 5},
		cands: []repository.ChunkCandidate{{Hypertable: "h", Schema: "s", Name: "a", Bytes: 1 << 30}}}
	if st := runEmergencyPass(newTestEmergency(repo, EmergencyOn), repo); st.Reason != "policy_running" || repo.compressedNames() != "" {
		t.Fatalf("status %#v compressed %v", st, repo.compressedNames())
	}

	// Another holder of the storage maintenance lock: the reclaim job (C6) or
	// a pass of another API process.
	repo = &fakeEmergencyRepo{locked: true, disk: &FSUsage{Total: 100, Used: 95, Avail: 5}}
	if st := runEmergencyPass(newTestEmergency(repo, EmergencyOn), repo); st.Reason != "another_pass_running" {
		t.Fatalf("status %#v", st)
	}
}

func TestEmergencyDryRunAndOff(t *testing.T) {
	repo := &fakeEmergencyRepo{
		cands: []repository.ChunkCandidate{{Hypertable: "h", Schema: "s", Name: "a", Bytes: 100 << 20}},
		disk:  &FSUsage{Total: uint64(100 * diskGiB), Used: uint64(91 * diskGiB), Avail: uint64(9 * diskGiB)},
	}
	e := newTestEmergency(repo, EmergencyDryRun)
	if p := e.Plan(context.Background(), *repo.disk); p.Action != "dry_run" || p.Chunks != 1 || p.Reclaimable <= 0 {
		t.Fatalf("plan = %#v", p)
	}
	st := runEmergencyPass(e, repo)
	if repo.compressedNames() != "" {
		t.Fatal("dry run compressed a chunk")
	}
	if st.State != "done" || st.Reason != "dry_run" || st.ChunksTotal != 1 || st.ChunksDone != 0 {
		t.Fatalf("dry-run status = %#v", st)
	}
	off := newTestEmergency(repo, EmergencyOff)
	off.TriggerAsync(*repo.disk)
	off.Wait()
	if p := off.Plan(context.Background(), *repo.disk); p.Action != "disabled" || off.Status().State != "idle" || off.Status().Mode != "off" {
		t.Fatalf("off: plan %#v status %#v", p, off.Status())
	}
}

func TestEmergencyPlanSaysWhenItCannotHelp(t *testing.T) {
	repo := &fakeEmergencyRepo{disk: &FSUsage{Total: uint64(100 * diskGiB), Used: uint64(99 * diskGiB), Avail: uint64(1 * diskGiB)}}
	e := newTestEmergency(repo, EmergencyOn)
	if p := e.Plan(context.Background(), *repo.disk); p.Action != "nothing_to_compress" {
		t.Fatalf("no candidates: %#v", p)
	}
	repo.cands = []repository.ChunkCandidate{{Hypertable: "h", Schema: "s", Name: "a", Bytes: 4 * diskGiB}}
	if p := e.Plan(context.Background(), *repo.disk); p.Action != "insufficient_space" {
		t.Fatalf("no room: %#v", p)
	}
}

func TestEmergencyRetryBackoff(t *testing.T) {
	repo := &fakeEmergencyRepo{disk: &FSUsage{Total: 100, Used: 95, Avail: 5}}
	e := newTestEmergency(repo, EmergencyOn)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	started := runEmergencyPass(e, repo).StartedAt
	now = now.Add(4 * time.Minute) // inside the 5-minute window after a finished pass
	if runEmergencyPass(e, repo).StartedAt != started {
		t.Fatal("a second pass started inside the backoff window")
	}
	now = now.Add(2 * time.Minute)
	if runEmergencyPass(e, repo).StartedAt == started {
		t.Fatal("no pass after the backoff window")
	}
}

// At 92% with nothing left to compress, a pass runs every five minutes. It
// must say so once, not 288 times a day.
func TestEmergencyRepeatedNoOpIsLoggedOnce(t *testing.T) {
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()

	repo := &fakeEmergencyRepo{disk: &FSUsage{Total: 100, Used: 95, Avail: 5}}
	e := newTestEmergency(repo, EmergencyOn)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	var mirrored int
	e.SetSystemLog(func(repository.SystemLogLevel, string) { mirrored++ })
	for i := 0; i < 5; i++ {
		runEmergencyPass(e, repo)
		now = now.Add(6 * time.Minute)
	}
	if n := strings.Count(buf.String(), "nothing_to_compress"); n != 1 || mirrored != 1 {
		t.Fatalf("logged %d times, mirrored %d times:\n%s", n, mirrored, buf.String())
	}

	// Something to do again: it is reported, and so is the next no-op.
	repo.cands = []repository.ChunkCandidate{{Hypertable: "h", Schema: "s", Name: "a", Bytes: 100 << 20}}
	repo.disk = &FSUsage{Total: uint64(100 * diskGiB), Used: uint64(91 * diskGiB), Avail: uint64(9 * diskGiB)}
	runEmergencyPass(e, repo)
	now = now.Add(6 * time.Minute)
	runEmergencyPass(e, repo)
	if n := strings.Count(buf.String(), "nothing_to_compress"); n != 2 || !strings.Contains(buf.String(), "compressed s.a") {
		t.Fatalf("after a real pass:\n%s", buf.String())
	}
}

// Stopping the API cancels a pass between chunks; the status says so instead
// of blaming the database.
func TestEmergencyStopsWithTheAPI(t *testing.T) {
	repo := &fakeEmergencyRepo{
		cands: []repository.ChunkCandidate{
			{Hypertable: "h", Schema: "s", Name: "a", Bytes: 100 << 20},
			{Hypertable: "h", Schema: "s", Name: "b", Bytes: 200 << 20},
		},
		disk: &FSUsage{Total: uint64(100 * diskGiB), Used: uint64(91 * diskGiB), Avail: uint64(9 * diskGiB)},
	}
	base, cancel := context.WithCancel(context.Background())
	e := NewEmergencyCompressor(base, repo, func(context.Context) (*FSUsage, error) {
		d := *repo.disk
		return &d, nil
	}, EmergencyOn)
	e.sleep = sleepCtx
	repo.onCompress = func(name string) {
		if name == "a" {
			cancel() // SIGTERM while the first chunk compresses
		}
	}
	e.TriggerAsync(*repo.disk)
	e.Wait()
	if st := e.Status(); st.Reason != "stopped" || repo.compressedNames() != "a" {
		t.Fatalf("status %#v compressed %v", st, repo.compressedNames())
	}
}

func TestCompressNeedIsPessimistic(t *testing.T) {
	// Measured peak extra space was the compressed size (131.9 MB chunk at 15x:
	// ~8 MB; 125 MB at 2.4x: 53 MB). The estimate must cover both with room.
	if need := compressNeed(131_900_000, 15.3); need < 53_000_000 {
		t.Fatalf("need %d is below the worst measured peak", need)
	}
	if need := compressNeed(125_000_000, 2.36); need < 106_000_000 {
		t.Fatalf("need %d is below compressed+WAL for a 2.4x chunk", need)
	}
	if reserveFor(10<<30) != 256<<20 || reserveFor(400<<30) != (400<<30)/200 {
		t.Fatal("reserve must be 0.5% of the disk, at least 256 MiB")
	}
}

func TestParseEmergencyMode(t *testing.T) {
	for v, want := range map[string]EmergencyMode{"": EmergencyOn, "on": EmergencyOn, "OFF": EmergencyOff, "dryrun": EmergencyDryRun, "dry-run": EmergencyDryRun} {
		if got, ok := ParseEmergencyMode(v); !ok || got != want {
			t.Errorf("%q -> %s, %v", v, got, ok)
		}
	}
	if got, ok := ParseEmergencyMode("of"); ok || got != EmergencyOn {
		t.Errorf("a typo must be reported and fall back to on, got %s %v", got, ok)
	}
}

// ── the guard and the compressor together ──────────────────────────────────

type fakeDiskEmergency struct {
	triggered int
	action    string
}

func (f *fakeDiskEmergency) Plan(context.Context, FSUsage) EmergencyPlan {
	return EmergencyPlan{Action: f.action}
}
func (f *fakeDiskEmergency) TriggerAsync(FSUsage) { f.triggered++ }
func (f *fakeDiskEmergency) Status() model.EmergencyCompressionStatus {
	return model.EmergencyCompressionStatus{Mode: "on", State: "running", ChunksDone: 1, ChunksTotal: 2}
}

// Critical on the database's disk starts a pass, and the critical message says
// what NPG is doing about it.
func TestDiskGuardStartsEmergencyCompressionOnCriticalDatabaseDisk(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	em := &fakeDiskEmergency{action: "emergency_compression"}
	g.emerg = em
	for _, p := range []float64{86, 86, 91, 91, 91} {
		diskTickAt(g, u, c, p)
	}
	if em.triggered == 0 {
		t.Fatal("critical on the database disk did not start an emergency compression")
	}
	crit := store.enqueued[len(store.enqueued)-1]
	if crit.Event != eventDiskCritical || crit.Fields["action"] != "emergency_compression" {
		t.Fatalf("critical message = %s %#v", crit.Event, crit.Fields)
	}
	st := g.Status(context.Background())
	if st.Emergency == nil || st.Emergency.State != "running" || st.Health().Emergency == nil {
		t.Fatalf("status emergency = %#v", st.Emergency)
	}
}

// After a restart the level comes from notification_state. If the disk was
// cleaned up meanwhile, that stale "critical" must not start a pass on its
// first tick (found in the boot smoke: a pass ran at 55% with 85/90/80). Inside
// the hysteresis band (85-90% after a critical episode) it keeps compressing.
func TestDiskGuardRestoredCriticalStateDoesNotCompressAHealthyDisk(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	em := &fakeDiskEmergency{action: "emergency_compression"}
	g.emerg = em
	store.state[eventDiskLow+"|db"] = stateFailing
	store.state[eventDiskCritical+"|db"] = stateFailing
	diskTickAt(g, u, c, 55)
	if em.triggered != 0 {
		t.Fatal("a stale critical state started an emergency pass at 55%")
	}
	diskTickAt(g, u, c, 55)
	if got := diskEvents(store); len(got) != 1 || got[0] != "disk.space_recovered/resolved" {
		t.Fatalf("got %v, want one recovery", got)
	}

	g2, u2, store2, c2 := newTestDiskGuard(t)
	em2 := &fakeDiskEmergency{action: "emergency_compression"}
	g2.emerg = em2
	store2.state[eventDiskLow+"|db"] = stateFailing
	store2.state[eventDiskCritical+"|db"] = stateFailing
	diskTickAt(g2, u2, c2, 87) // still critical under hysteresis
	if em2.triggered != 1 {
		t.Fatalf("triggered %d times at 87%% after a critical episode, want 1", em2.triggered)
	}
}

// Emergency compression only helps the disk the database is on.
func TestDiskGuardEmergencyOnlyForDatabaseDisk(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	em := &fakeDiskEmergency{action: "emergency_compression"}
	g.emerg = em
	u.roles["db"] = []DiskRole{DiskRoleNginxLogs}
	diskTickAt(g, u, c, 95)
	diskTickAt(g, u, c, 95)
	if em.triggered != 0 {
		t.Fatal("emergency compression started for a disk without the database")
	}
	for _, m := range store.enqueued {
		if m.Fields["action"] != "" {
			t.Fatalf("a disk without the database got an action: %#v", m.Fields)
		}
	}
}

func TestDiskCriticalActionIsTranslated(t *testing.T) {
	msg := SampleMessage(LangKorean, "disk.space_critical")
	text := plainText(LangKorean, msg)
	if !strings.Contains(text, "지난 로그 청크를 지금 압축합니다") || !strings.Contains(text, "조치") || strings.Contains(text, "emergency_compression") {
		t.Errorf("ko text:\n%s", text)
	}
	if msg.Fields["action"] != "emergency_compression" {
		t.Errorf("fields must keep the code: %#v", msg.Fields)
	}
	for _, action := range []string{"emergency_compression", "nothing_to_compress", "insufficient_space", "disabled", "dry_run", "unavailable"} {
		for _, lang := range []string{LangEnglish, LangKorean} {
			if lookupValueLabel(lang, "action", action) == "" {
				t.Errorf("%s has no %s wording", action, lang)
			}
		}
	}
	store := newFakeStore("disk.space_critical")
	_ = NewNotificationServiceWithStore(store).EmitTransition(context.Background(), "disk.space_critical", "db", true, "",
		map[string]string{"action": "dry_run"})
	if store.enqueued[0].Fields["action"] != "dry_run" {
		t.Error("action must pass the allowlist")
	}
}

// panickyRepo blows up mid-pass.
type panickyRepo struct{ fakeEmergencyRepo }

func (p *panickyRepo) CompressionCandidates(context.Context, int64) ([]repository.ChunkCandidate, error) {
	panic("unexpected nil in a chunk row")
}

// A pass runs off the scheduler's goroutine; a panic in it must end the pass,
// not the API.
func TestEmergencyPassSurvivesAPanic(t *testing.T) {
	repo := &panickyRepo{fakeEmergencyRepo{disk: &FSUsage{Total: 100, Used: 95, Avail: 5}}}
	e := NewEmergencyCompressor(context.Background(), repo, func(context.Context) (*FSUsage, error) {
		d := *repo.disk
		return &d, nil
	}, EmergencyOn)
	e.TriggerAsync(*repo.disk)
	e.Wait()
	if st := e.Status(); st.State != "blocked" || st.Reason != "error" {
		t.Fatalf("status after a panic = %#v", st)
	}
	if e.running.Load() {
		t.Fatal("the pass slot stayed taken after a panic")
	}
}
