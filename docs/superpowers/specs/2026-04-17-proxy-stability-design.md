# Reverse Proxy Stability + Observability — Design Spec

> **Date:** 2026-04-17
> **Target Version:** 2.11.0 (post-2.10.0)
> **Scope:** Defensive reload with retry/rollback, post-reload health verification, Prometheus observability
> **Authors:** Pair session (user: svrforum / jmlee0108@toss.im)

## 1. Background

v2.10.0 cleanup은 구조적 부채를 해소했지만, **핵심 리버스 프록시 동작 경로 자체의 안정성 강화는 범위 밖**이었다. 현재 `testAndReloadNginx` (api/internal/nginx/manager.go:183)은 다음 약점을 가진다:

1. **Reload 실패 시 retry/rollback 부재** — Docker 일시 오류, 파일시스템 일시 지연 등 transient 실패가 곧바로 사용자 에러로 전파
2. **Reload 후 health 검증 없음** — `nginx -s reload` 종료코드 0 = "성공"으로 간주. 실제 worker가 떴는지, /health가 200을 반환하는지 확인 안 함. 빈 config가 올라가도 프로세스는 살아있음
3. **관측성 부족** — reload 성공률/latency/실패 원인이 로그에만 남아 있고 메트릭/대시보드 없음. 운영 관점에서 "최근 24h에 몇 번 실패했는가" 불명

**연관 컨텍스트**: `SyncAllConfigs`의 auto-recovery는 startup / 다중 호스트 재생성 시에만 작동. **단일 호스트 update/delete 경로는 fail-fast**로 남아 있음.

### 범위 확정 (브레인스토밍 결과)

- **안정성 레벨:** **C (방어적 + 사후검증 + 관측성)** — D(zero-downtime) 제외
- **PR 전략:** **A (4개 독립 PR 순차)** — Phase별 회귀 즉시 롤백 가능
- **테스트 전략:** **Phase 0에 특성 테스트 먼저** — 리팩토링이 아닌 기능 추가지만 안전망 선행

### 범위 밖 (명시적 배제)

- **Per-host mutex** (global mutex 세분화) — 현재 호스트 규모(~10개)에서 premature optimization
- **Config 집계 Redis 캐시** — 캐시 무효화 복잡도 높음, 별도 프로젝트
- **Blue-green / canary deployment** — 규모 대비 과도
- **UI 대시보드 메트릭 시각화** — Phase 3은 `/metrics` 엔드포인트 노출까지만
- **외부 Prometheus 서버 배포** — 사용자가 스크래핑 설정하는 것은 운영 영역

---

## 2. Architecture Overview

4개 Phase × 4개 PR. Phase 1~3는 manager.go를 점진적 확장. Phase 3은 기존 코드에 observability 주입.

| Phase | PR | 브랜치 | 리스크 | 의존 |
|-------|-----|--------|--------|------|
| 0 | `test(nginx): add reload failure scenario tests` | `stability0/reload-tests` | 🟢 | - |
| 1 | `feat(nginx): add reload retry and config rollback` | `stability1/retry-rollback` | 🟡 | 0 |
| 2 | `feat(nginx): verify health after reload with auto-revert` | `stability2/health-verify` | 🟡 | 1 |
| 3 | `feat(observability): expose Prometheus metrics for proxy ops` | `stability3/metrics` | 🟢 | 2 |

### 검증 게이트 (모든 Phase 공통)

1. `docker compose -f docker-compose.dev.yml build api` 성공
2. `go test ./...` green (특히 확장된 특성 테스트)
3. `cd test/e2e && npx playwright test specs/proxy-host/ specs/security/` green
4. Manual smoke: 호스트 생성 → nginx config 반영 + `/health` 200 + `/metrics` 노출 (Phase 3부터)

### 목표 지표

| 영역 | 현재 | Phase 3 완료 후 |
|------|------|-----------------|
| Transient 실패 자동 복구 | ❌ | ✅ 2회 지수 백오프 retry |
| Config 실패 시 rollback | ❌ (단일 호스트) | ✅ 자동 이전 config 복원 |
| Reload 후 health 검증 | ❌ | ✅ worker + HTTP probe |
| Reload 메트릭 노출 | ❌ | ✅ Prometheus `/metrics` |
| 테스트 커버리지 (reload 경로) | 간접 (1 case) | 직접 (7+ cases) |

---

## 3. Phase 0 — Reload 특성 테스트

### 3.1 목표

Phase 1~2에서 추가될 retry/rollback/health 로직의 **before-state behavior**를 캡처. 테스트는 "현재는 이렇게 동작한다"를 고정, Phase 1-2가 이를 **확장**(기존 성공 케이스 그대로 + 실패 케이스에서 신규 복구 동작)한다.

### 3.2 대상 파일

**Create:** `api/internal/nginx/reload_characterization_test.go`

### 3.3 Fake NginxCLI 스텁

Docker exec 호출을 테스트에 노출할 수 있게 **좁은 인터페이스** 추출. manager.go에서 이미 `docker exec` 호출 몇 군데를 프라이빗 메서드로 분리.

```go
// api/internal/nginx/nginx_cli.go (신규)
type nginxCLI interface {
    Test(ctx context.Context) error          // nginx -t
    Reload(ctx context.Context) error        // nginx -s reload
}

type dockerNginxCLI struct {
    containerName string
}

func (d *dockerNginxCLI) Test(ctx context.Context) error {
    // 기존 docker exec nginx -t 로직 추출
}
func (d *dockerNginxCLI) Reload(ctx context.Context) error {
    // 기존 docker exec nginx -s reload 로직 추출
}
```

Manager 구조체에 `cli nginxCLI` 필드 추가 (기본값 `dockerNginxCLI{container}`, 테스트에서는 fake 주입).

### 3.4 케이스 (4개)

```go
func TestTestAndReloadNginx_Success(t *testing.T) {
    // fake: Test=nil, Reload=nil → 에러 없음
}

func TestTestAndReloadNginx_TestFails_SyntaxError(t *testing.T) {
    // fake: Test=errors.New("nginx: [emerg] ...syntax error..."), Reload=n/a
    // 기대: 에러 반환, Reload 호출 0회
}

func TestTestAndReloadNginx_ReloadFails(t *testing.T) {
    // fake: Test=nil, Reload=errors.New("reload failed")
    // 기대: 에러 반환
}

func TestTestAndReloadNginx_TransientDockerError(t *testing.T) {
    // fake: Test=errors.New("docker: connection refused")
    // 기대 (Phase 0 시점): 에러 반환 (retry 없음)
    // Phase 1에서 이 테스트가 '3회 시도 후 에러' 또는 '성공'으로 재정의됨
}
```

### 3.5 성공 기준

`go test ./internal/nginx/ -run TestTestAndReloadNginx -v` → 4/4 PASS.

---

## 4. Phase 1 — Retry + Rollback

### 4.1 파일 변경

**Modify:** `api/internal/nginx/manager.go`
**Modify:** `api/internal/nginx/reload_characterization_test.go` (케이스 확장)
**Create:** `api/internal/nginx/reload_retry.go` (새 헬퍼들)

### 4.2 상수

추가 위치: `api/internal/config/constants.go`

```go
const (
    ReloadMaxRetries     = 2                      // 최대 재시도 (총 시도 3회)
    ReloadRetryBaseDelay = 500 * time.Millisecond // 500ms, 1s, 2s 지수 백오프
)

// Transient 에러 패턴 — 이 패턴 매치 시에만 retry
// syntax error처럼 config 자체 문제는 retry 해도 의미 없음 → 즉시 반환
var reloadTransientErrorPattern = regexp.MustCompile(
    `(docker.*connection refused|docker.*cannot connect|i/o timeout|resource temporarily unavailable|context deadline exceeded)`,
)
```

### 4.3 Rollback 메커니즘

#### writeFileAtomicWithBackup

기존 `writeFileAtomic`을 래핑:

```go
// manager.go
func (m *Manager) writeFileAtomicWithBackup(path string, data []byte, perm os.FileMode) error {
    // 1. 기존 path가 존재하면 path+".backup"으로 rename
    //    (기존 .backup은 덮어씀 — 항상 "마지막 성공 config" 만 보관)
    if _, err := os.Stat(path); err == nil {
        if err := os.Rename(path, path+".backup"); err != nil {
            return fmt.Errorf("backup current config: %w", err)
        }
    }
    // 2. 기존 atomic write (temp → fsync → rename)
    return m.writeFileAtomic(path, data, perm)
}
```

#### rollbackConfig

```go
// reload_retry.go (신규 파일)
func (m *Manager) rollbackConfig(path string) error {
    backupPath := path + ".backup"
    if _, err := os.Stat(backupPath); err == nil {
        // 기존 파일 있었음 → backup으로 원복
        return os.Rename(backupPath, path)
    }
    // 신규 호스트 (backup 없음) → 생성된 config 삭제
    if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
        return err
    }
    return nil
}
```

**중요**: Rollback은 단일 파일 단위. `GenerateConfigAndReload`가 `{domain}.conf` 1개만 쓰므로 이 수준에서 충분. WAF host config도 별도 경로 + 별도 rollback.

### 4.4 재시도 루프 (testAndReloadNginx 재작성)

```go
// reload_retry.go 또는 manager.go
func (m *Manager) testAndReloadNginxWithRetry(ctx context.Context, changedPaths []string) error {
    var lastErr error
    delay := config.ReloadRetryBaseDelay

    for attempt := 0; attempt <= config.ReloadMaxRetries; attempt++ {
        if attempt > 0 {
            log.Printf("[NginxReload] Retry attempt %d after %v (last error: %v)", attempt, delay, lastErr)
            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return ctx.Err()
            }
            delay *= 2
        }

        // 1. nginx -t
        if err := m.cli.Test(ctx); err != nil {
            if isTransient(err) {
                lastErr = err
                continue
            }
            // syntax error 등 non-transient → rollback 후 즉시 반환
            for _, p := range changedPaths {
                _ = m.rollbackConfig(p)
            }
            _ = m.cli.Test(ctx)  // 복구 검증 (best-effort)
            return fmt.Errorf("nginx config invalid: %w", err)
        }

        // 2. nginx -s reload
        if err := m.cli.Reload(ctx); err != nil {
            if isTransient(err) {
                lastErr = err
                continue
            }
            // reload 실패 (non-transient)
            for _, p := range changedPaths {
                _ = m.rollbackConfig(p)
            }
            _ = m.cli.Reload(ctx)  // 복구 검증
            return fmt.Errorf("nginx reload failed: %w", err)
        }

        return nil  // 성공
    }

    // 모든 재시도 소진 → rollback
    for _, p := range changedPaths {
        _ = m.rollbackConfig(p)
    }
    return fmt.Errorf("nginx reload failed after %d attempts: %w", config.ReloadMaxRetries+1, lastErr)
}

func isTransient(err error) bool {
    if err == nil {
        return false
    }
    return reloadTransientErrorPattern.MatchString(err.Error())
}
```

### 4.5 Caller 경로 업데이트

기존 `GenerateConfigAndReload`, `GenerateHostWAFConfig` 등의 호출 지점에서:

```go
// Before:
if err := m.testAndReloadNginx(ctx); err != nil { return err }

// After:
if err := m.testAndReloadNginxWithRetry(ctx, []string{configPath}); err != nil { return err }
```

여러 config 파일을 함께 수정하는 경로(proxy host + WAF config)에서는 `changedPaths = []string{proxyPath, wafPath}` 전달.

### 4.6 테스트 확장

Phase 0의 4개 케이스를 다음과 같이 **재정의/추가**:

```go
// 재정의: TransientDockerError는 이제 retry 후 성공하면 에러 없음
func TestTestAndReloadNginx_TransientRecovery(t *testing.T) {
    // fake: Test={첫 시도 connection refused, 두 번째 nil}, Reload=nil
    // 기대: retry 1회 후 성공 (에러 없음), Test 호출 2회
}

// 신규:
func TestTestAndReloadNginx_TransientExhausted_Rollback(t *testing.T) {
    // fake: Test=항상 connection refused, Reload=n/a
    // Manager에 fake filesystem 주입 (또는 실제 temp dir)
    // 1. domain.conf가 이미 존재하고 내용 "OLD"
    // 2. testAndReloadNginxWithRetry 호출 전에 "NEW" 내용을 writeFileAtomicWithBackup
    // 3. reload 실패 → rollback 발생
    // 기대: domain.conf 파일의 내용이 "OLD"로 복원됨, 에러 반환, Test 호출 3회
}

func TestTestAndReloadNginx_NonTransientImmediateFail(t *testing.T) {
    // fake: Test=errors.New("nginx: [emerg] syntax error"), Reload=n/a
    // 기대: 즉시 에러, Test 호출 1회 (retry 없음), rollback 발생
}

func TestTestAndReloadNginx_SuccessNoRetryNoRollback(t *testing.T) {
    // fake: Test=nil, Reload=nil
    // 기대: 성공, rollback 미발생 (.backup 파일 남아 있음)
}
```

### 4.7 성공 기준

- `go test ./internal/nginx/... -run TestTestAndReloadNginx -v` → 모든 케이스 PASS
- 기존 특성 테스트 green 유지
- E2E `specs/proxy-host/sync.spec.ts` green

---

## 5. Phase 2 — Post-Reload Health Verification

### 5.1 파일 변경

**Create:** `api/internal/nginx/health_probe.go`
**Modify:** `api/internal/nginx/manager.go`
**Modify:** `api/internal/config/constants.go`

### 5.2 Probe 전략 (2단계)

#### 5.2.1 Worker Ready 확인

`nginx -s reload`는 graceful — 기존 worker는 처리 중인 요청 완료 후 종료, 새 worker 시작. reload 성공 반환 ≠ 새 worker 준비 완료.

```go
// docker exec {container} sh -c "ps ax | grep -c 'nginx: worker' | head -1"
// 또는 nginx -T로 로드된 config 검증 (heavy)
// 선택: ps 방식 (빠름)
func (p *HealthProber) waitForWorkersReady(ctx context.Context, timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        workers, err := p.countWorkers(ctx)
        if err == nil && workers > 0 {
            return nil
        }
        time.Sleep(100 * time.Millisecond)
    }
    return fmt.Errorf("nginx workers not ready after %v", timeout)
}
```

#### 5.2.2 HTTP probe

기본 서버(zzz_default.conf)가 `/health` 엔드포인트 제공 → 여기를 probe.

```go
// docker exec {container} curl -sf --max-time 0.5 http://127.0.0.1:80/health
// Note: 모든 nginx 동적 모듈과 server block이 로드된 상태에서만 200 반환
func (p *HealthProber) probeHTTP(ctx context.Context) error {
    cmd := exec.CommandContext(ctx, "docker", "exec", p.containerName,
        "sh", "-c", "curl -sf --max-time 0.5 http://127.0.0.1:80/health")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("health probe failed: %w", err)
    }
    return nil
}
```

### 5.3 통합 흐름

```go
// manager.go, testAndReloadNginxWithRetry의 reload 성공 분기 뒤:
if err := m.cli.Reload(ctx); err != nil {
    // Phase 1 retry/rollback 로직
}

// === Phase 2 추가 ===
if m.healthProber != nil && !m.healthProbeDisabled {
    if err := m.healthProber.Verify(ctx); err != nil {
        log.Printf("[NginxReload] Post-reload health probe failed: %v — rolling back", err)
        for _, p := range changedPaths {
            _ = m.rollbackConfig(p)
        }
        _ = m.cli.Reload(ctx)  // 복구 reload
        // 복구 reload도 실패하면 다음 SyncAllConfigs 사이클에서 auto-recovery
        return fmt.Errorf("post-reload health verification failed, rolled back: %w", err)
    }
}

return nil  // 성공
```

### 5.4 상수

```go
// constants.go
const (
    HealthProbeTimeout          = 500 * time.Millisecond
    WorkerReadyTimeout          = 2 * time.Second
    HealthProbeFailureThreshold = 2 // 연속 실패 N번 시 revert
)
```

### 5.5 Opt-out 메커니즘

환경변수 `NPG_HEALTH_PROBE=false`로 비활성화 가능. 기본값은 활성 (안전 우선).

```go
// bootstrap/storage.go or services.go에서 Manager 생성 시:
healthProbeDisabled := os.Getenv("NPG_HEALTH_PROBE") == "false"
```

### 5.6 테스트

**Create:** `api/internal/nginx/health_probe_test.go`

- `TestHealthProber_WorkersReady` — fake docker exec가 "3 workers" 반환 → 성공
- `TestHealthProber_WorkersNotReady_Timeout` — fake가 항상 "0" 반환 → 2s 후 timeout 에러
- `TestHealthProber_HTTPProbeSuccess` — fake curl exit 0 → 성공
- `TestHealthProber_HTTPProbeFail` — fake curl exit 7 → 에러

그리고 **Phase 1의 테스트 확장**:
- `TestTestAndReloadNginx_HealthProbeFail_Rollback` — reload 성공 but health probe 실패 → config rollback 발생, 에러 반환

### 5.7 성공 기준

- 신규 `health_probe_test.go` 전체 PASS
- Phase 1 테스트 확장분 PASS
- Manual: 일부러 empty config 주입 → health probe 실패 감지, 이전 config로 복원
- E2E 전체 green

---

## 6. Phase 3 — Prometheus Metrics

### 6.1 파일 변경

**Create:** `api/internal/metrics/metrics.go` — 모든 메트릭 정의
**Create:** `api/internal/handler/metrics.go` — `/metrics` 핸들러
**Modify:** `api/internal/nginx/manager.go` — reload 경로에 카운터/히스토그램 주입
**Modify:** `api/internal/nginx/health_probe.go` — probe 경로에 카운터 주입
**Modify:** `api/internal/service/proxy_host_sync.go` — auto-recovery 경로에 카운터
**Modify:** `api/internal/bootstrap/routes.go` — `/metrics` 라우트 등록
**Modify:** `api/go.mod` — `github.com/prometheus/client_golang` 의존성 추가

### 6.2 메트릭 카탈로그

```go
// api/internal/metrics/metrics.go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    // Counters — 누적 이벤트
    NginxReloadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "nginx_reload_total",
        Help: "Total nginx reload attempts by final status",
    }, []string{"status"}) // success | failed

    NginxReloadRetryTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "nginx_reload_retry_total",
        Help: "Total individual retry attempts during reload",
    })

    NginxReloadRollbackTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "nginx_reload_rollback_total",
        Help: "Total config rollbacks by reason",
    }, []string{"reason"}) // test_failed | reload_failed | health_failed | retry_exhausted

    NginxHealthProbeFailureTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "nginx_health_probe_failure_total",
        Help: "Total health probe failures by probe type",
    }, []string{"probe"}) // workers | http

    NginxAutoRecoveryTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "nginx_auto_recovery_total",
        Help: "Total hosts isolated by SyncAllConfigs auto-recovery",
    })

    // Histograms — 지연시간 분포
    NginxReloadDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "nginx_reload_duration_seconds",
        Help:    "Time from testAndReloadNginxWithRetry start to success/failure",
        Buckets: prometheus.ExponentialBuckets(0.05, 2, 9), // 50ms ~ 12.8s
    })

    NginxConfigGenerationDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "nginx_config_generation_duration_seconds",
        Help:    "Time to aggregate config data + render template",
        Buckets: prometheus.DefBuckets,
    })

    NginxHealthProbeDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "nginx_health_probe_duration_seconds",
        Help:    "Time for each probe type",
        Buckets: prometheus.ExponentialBuckets(0.01, 2, 8), // 10ms ~ 1.28s
    }, []string{"probe"}) // workers | http

    // Gauges — 현재 상태
    NginxConfigStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
        Name: "nginx_config_status",
        Help: "Current config status per host (1=ok, 0=error)",
    }, []string{"host_id"})

    NginxLastReloadTimestampSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "nginx_last_reload_timestamp_seconds",
        Help: "Unix timestamp of last successful reload",
    })
)

func init() {
    prometheus.MustRegister(
        NginxReloadTotal,
        NginxReloadRetryTotal,
        NginxReloadRollbackTotal,
        NginxHealthProbeFailureTotal,
        NginxAutoRecoveryTotal,
        NginxReloadDurationSeconds,
        NginxConfigGenerationDurationSeconds,
        NginxHealthProbeDurationSeconds,
        NginxConfigStatus,
        NginxLastReloadTimestampSeconds,
    )
}
```

### 6.3 Handler

```go
// api/internal/handler/metrics.go
package handler

import (
    "github.com/labstack/echo/v4"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsHandler struct{}

func NewMetricsHandler() *MetricsHandler { return &MetricsHandler{} }

func (h *MetricsHandler) ServeMetrics(c echo.Context) error {
    promhttp.Handler().ServeHTTP(c.Response().Writer, c.Request())
    return nil
}
```

### 6.4 라우트 등록

```go
// bootstrap/routes.go — RegisterRoutes 맨 앞에 (인증 필요 없는 엔드포인트와 같은 레벨)
e.GET("/metrics", c.Handlers.Metrics.ServeMetrics)
```

**보안**: `/metrics`는 기본으로 **API 토큰 미검증** 공개 엔드포인트로 등록. 운영자가 외부 노출하려면 자체 ACL/방화벽/API 토큰 미들웨어 추가 책임. docker-compose 내부 네트워크에서만 접근 권장.

> 이 설계 선택 근거: Prometheus 스크래핑은 보통 기본 인증 없이 내부 네트워크에서 이루어짐. 인증을 요구하면 대부분의 Prometheus 서버 설정이 더 복잡해짐. 트레이드오프: `/metrics` 노출 ≈ 시스템 동작 지표 노출 (호스트 수, 오류 수 등). 민감하지 않은 수준.

### 6.5 주입 지점

#### manager.go
```go
func (m *Manager) testAndReloadNginxWithRetry(ctx context.Context, changedPaths []string) error {
    start := time.Now()
    defer func() {
        metrics.NginxReloadDurationSeconds.Observe(time.Since(start).Seconds())
    }()

    // ... retry loop ...
    if retried { metrics.NginxReloadRetryTotal.Inc() }
    // rollback branches:
    metrics.NginxReloadRollbackTotal.WithLabelValues("test_failed").Inc()
    // or "reload_failed" / "health_failed" / "retry_exhausted"

    // success:
    metrics.NginxReloadTotal.WithLabelValues("success").Inc()
    metrics.NginxLastReloadTimestampSeconds.SetToCurrentTime()
    // failure:
    metrics.NginxReloadTotal.WithLabelValues("failed").Inc()
}
```

#### Config generation
```go
// GenerateConfigFull 내부 또는 caller
start := time.Now()
err := proxyHostTemplate.Execute(&buf, data)
metrics.NginxConfigGenerationDurationSeconds.Observe(time.Since(start).Seconds())
```

#### proxy_host_sync.go
```go
// runAutoRecovery 내부, 각 에러 호스트 격리 시
metrics.NginxAutoRecoveryTotal.Inc()
// 각 호스트의 config_status 업데이트 시
metrics.NginxConfigStatus.WithLabelValues(hostID).Set(statusValue(status))
```

### 6.6 테스트

**Create:** `api/internal/metrics/metrics_test.go`

- Counter 증가 테스트 (각 메트릭 1회씩 Inc 호출 후 값 검증)
- `/metrics` 핸들러 테스트 (HTTP GET → Prometheus 포맷 텍스트 반환 확인)

### 6.7 성공 기준

- `go test ./internal/metrics/ -v` PASS
- `curl http://localhost:8080/metrics` 실행 시 Prometheus 포맷 메트릭 목록 반환
- Manual: 호스트 1개 생성 → `nginx_reload_total{status="success"}` 1 증가 확인
- E2E 전체 green

---

## 7. 커밋 / PR / 브랜치

### 7.1 커밋 규칙
- `type(scope): short description` (영문 72자 이내)
- 타입: Phase 0 = `test:`, Phase 1~3 = `feat:`/`feat(nginx):`/`feat(observability):`
- Claude 서명 금지
- 여러 논리 단위 있으면 여러 커밋 (한 Phase 내에서도)

### 7.2 PR 본문 템플릿
```markdown
## Scope
Phase N of proxy-stability — <description>
Spec: docs/superpowers/specs/2026-04-17-proxy-stability-design.md §N

## Changes
- <changes>

## Verification
- [x] `go test ./...` green
- [x] `docker compose build api` 성공
- [x] E2E `specs/proxy-host/`, `specs/security/` green
- [x] Manual smoke (if applicable)

## Out of scope
- <excluded items>
```

### 7.3 브랜치
- `stability0/reload-tests`
- `stability1/retry-rollback`
- `stability2/health-verify`
- `stability3/metrics`

---

## 8. Definition of Done

프로젝트 완료 조건:

1. 4개 PR 모두 `main` 머지
2. `release: v2.11.0` 커밋 생성, `v2.11.0` tag push
3. §2 목표 지표 전체 달성
4. `go test ./...` green (기존 33 + 신규 ~15 cases)
5. `cd test/e2e && npx playwright test specs/proxy-host/ specs/security/` green
6. `curl http://localhost:8080/metrics` → Prometheus 포맷 응답
7. Manual: 일부러 broken config 주입 → auto rollback + `/metrics`에 `rollback_total` 증가 확인

## 9. 예상 일정

| Phase | 예상 | 누적 |
|-------|------|------|
| 0 | 2h | 2h |
| 1 | 4h | 6h |
| 2 | 3h | 9h |
| 3 | 3h | 12h |

**총 ~12시간** 누적 작업. 병렬 dispatch 가능 여부:
- Phase 0~2는 manager.go 연쇄 변경 → **순차**
- Phase 3는 다른 파일 + manager.go에 주입만 → Phase 2 merge 후

→ 순차 실행, 실제 벽시계 ~2-3시간 예상 (Phase별 subagent + 리뷰 cycles).
