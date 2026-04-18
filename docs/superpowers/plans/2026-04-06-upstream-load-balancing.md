# Upstream 로드밸런싱 안정화 + GUI 통합 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 upstream/로드밸런싱 백엔드를 안정화하고, ProxyHostForm에 탭으로 GUI를 통합한다.

**Architecture:** Phase 1에서 백엔드 안정화(nginx reload 연동, 입력 검증, 에러 핸들링), Phase 2에서 기존 UpstreamPanel을 ProxyHostForm의 탭으로 리팩토링하여 연결한다. upstream은 독립 API로 저장되므로 기존 프록시 호스트 저장 흐름에 영향 없음.

**Tech Stack:** Go 1.24 (Echo v4), React 18 + TypeScript, PostgreSQL/TimescaleDB

**GitHub Issue:** #95

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `api/internal/service/security.go` | nginx config 재생성 트리거, 입력 검증 추가 |
| Modify | `api/internal/repository/upstream.go` | json.Unmarshal 에러 핸들링, 이름 검증 |
| Modify | `api/internal/nginx/proxy_host_template.go` | upstream 블록에 서버 개수 방어 조건 |
| Modify | `ui/src/components/proxy-host/types.ts` | TabType에 'upstream' 추가 |
| Modify | `ui/src/components/proxy-host/ProxyHostForm.tsx` | upstream 탭 연결 |
| Create | `ui/src/components/proxy-host/tabs/UpstreamTab.tsx` | 기존 UpstreamPanel → 탭 형태 리팩토링 |
| Modify | `ui/src/i18n/locales/ko/proxyHost.json` | upstream 번역 추가 |
| Modify | `ui/src/i18n/locales/en/proxyHost.json` | upstream 번역 추가 |

---

### Task 1: Backend — nginx config 재생성 트리거 추가

**Files:**
- Modify: `api/internal/service/security.go:180-193`

- [ ] **Step 1: Update UpsertUpstream to regenerate nginx config**

In `api/internal/service/security.go`, replace the `UpsertUpstream` method (lines 180-186):

```go
func (s *SecurityService) UpsertUpstream(ctx context.Context, proxyHostID string, req *model.CreateUpstreamRequest) (*model.Upstream, error) {
	// Validate load balance method
	if req.LoadBalance != "" {
		valid := false
		for _, m := range model.ValidLoadBalanceMethods {
			if req.LoadBalance == m {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid load_balance method: %s", req.LoadBalance)
		}
	}

	// Validate server addresses
	for i, srv := range req.Servers {
		if srv.Address == "" {
			return nil, fmt.Errorf("server %d: address is required", i+1)
		}
		if srv.Port < 0 || srv.Port > 65535 {
			return nil, fmt.Errorf("server %d: invalid port %d", i+1, srv.Port)
		}
	}

	upstream, err := s.upstreamRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert upstream: %w", err)
	}

	// Regenerate nginx config to apply upstream changes
	if s.proxyHostService != nil {
		if regenErr := s.proxyHostService.RegenerateConfigForHost(ctx, proxyHostID); regenErr != nil {
			log.Printf("[Upstream] Warning: failed to regenerate config for host %s: %v", proxyHostID, regenErr)
		}
	}

	return upstream, nil
}
```

Add `"log"` to the import block if not already present.

- [ ] **Step 2: Update DeleteUpstream to regenerate nginx config**

Replace the `DeleteUpstream` method (lines 188-193):

```go
func (s *SecurityService) DeleteUpstream(ctx context.Context, proxyHostID string) error {
	if err := s.upstreamRepo.Delete(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete upstream: %w", err)
	}

	// Regenerate nginx config to remove upstream block
	if s.proxyHostService != nil {
		if regenErr := s.proxyHostService.RegenerateConfigForHost(ctx, proxyHostID); regenErr != nil {
			log.Printf("[Upstream] Warning: failed to regenerate config after upstream delete for host %s: %v", proxyHostID, regenErr)
		}
	}

	return nil
}
```

- [ ] **Step 3: Commit**

```bash
git add api/internal/service/security.go
git commit -m "fix: trigger nginx config regeneration on upstream changes"
```

---

### Task 2: Backend — upstream 이름 검증 + JSON 에러 핸들링

**Files:**
- Modify: `api/internal/repository/upstream.go`

- [ ] **Step 1: Add name sanitization and JSON error handling**

Add `"fmt"` and `"regexp"` to the import block.

Add a name validation regex at the top of the file after imports:

```go
// validUpstreamName allows only alphanumeric characters and underscores
var validUpstreamName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
```

- [ ] **Step 2: Fix JSON Unmarshal error handling in GetByProxyHostID**

Replace lines 49-51:

```go
	if len(serversJSON) > 0 {
		if err := json.Unmarshal(serversJSON, &u.Servers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
	}
```

- [ ] **Step 3: Fix JSON Unmarshal in GetByID**

Replace lines 85-87:

```go
	if len(serversJSON) > 0 {
		if err := json.Unmarshal(serversJSON, &u.Servers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
	}
```

- [ ] **Step 4: Fix JSON Marshal and Unmarshal in Upsert**

Replace line 120:

```go
		var marshalErr error
		serversJSON, marshalErr = json.Marshal(servers)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to marshal servers JSON: %w", marshalErr)
		}
```

Add name validation after the name generation block (after line 131):

```go
	// Validate upstream name for nginx syntax safety
	if !validUpstreamName.MatchString(name) {
		return nil, fmt.Errorf("invalid upstream name: only alphanumeric and underscore allowed")
	}
```

Replace lines 176-178:

```go
	if len(returnedServersJSON) > 0 {
		if err := json.Unmarshal(returnedServersJSON, &u.Servers); err != nil {
			return nil, fmt.Errorf("failed to unmarshal returned servers JSON: %w", err)
		}
	}
```

- [ ] **Step 5: Fix JSON error handling in UpdateServerHealth**

Replace line 208:

```go
		if err := json.Unmarshal(serversJSON, &servers); err != nil {
			return fmt.Errorf("failed to unmarshal servers JSON: %w", err)
		}
```

Replace line 223:

```go
	updatedJSON, marshalErr := json.Marshal(servers)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal updated servers JSON: %w", marshalErr)
	}
```

- [ ] **Step 6: Fix JSON Unmarshal in ListWithHealthCheck**

Replace lines 263-265:

```go
		if len(serversJSON) > 0 {
			if err := json.Unmarshal(serversJSON, &u.Servers); err != nil {
				return nil, fmt.Errorf("failed to unmarshal servers JSON: %w", err)
			}
		}
```

- [ ] **Step 7: Commit**

```bash
git add api/internal/repository/upstream.go
git commit -m "fix: add upstream name validation and JSON error handling"
```

---

### Task 3: Backend — nginx 템플릿 방어 조건 추가

**Files:**
- Modify: `api/internal/nginx/proxy_host_template.go:71-88`

- [ ] **Step 1: Add server count check to upstream template block**

The current template at lines 71-88 only checks `{{if .Upstream}}`. Although `proxy_host_config.go:180` already filters `len(up.Servers) > 0`, add a defense-in-depth check in the template itself.

Replace lines 71-88:

```go
{{if and .Upstream .Upstream.Servers}}
# Upstream definition for load balancing
upstream {{.Upstream.Name}} {
{{if eq .Upstream.LoadBalance "least_conn"}}
    least_conn;
{{else if eq .Upstream.LoadBalance "ip_hash"}}
    ip_hash;
{{else if eq .Upstream.LoadBalance "random"}}
    random;
{{end}}
{{range .Upstream.Servers}}
    server {{.Address}}:{{.Port}}{{if ne .Weight 1}} weight={{.Weight}}{{end}}{{if ne .MaxFails 0}} max_fails={{.MaxFails}}{{end}}{{if ne .FailTimeout 0}} fail_timeout={{.FailTimeout}}s{{end}}{{if .IsBackup}} backup{{end}}{{if .IsDown}} down{{end}};
{{end}}
{{if .Upstream.Keepalive}}
    keepalive {{.Upstream.Keepalive}};
{{end}}
}
{{end}}
```

Also update all `proxy_pass` references throughout the template. Find all occurrences like:

```
{{if .Upstream}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass ...{{end}}
```

And change them to:

```
{{if and .Upstream .Upstream.Servers}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass ...{{end}}
```

There are approximately 6 such occurrences. Use `replace_all` or find each one. Also update line 13:

```
# Upstream: {{if and .Upstream .Upstream.Servers}}{{.Upstream.Name}} ({{.Upstream.LoadBalance}}){{else}}none{{end}}
```

- [ ] **Step 2: Commit**

```bash
git add api/internal/nginx/proxy_host_template.go
git commit -m "fix: add defense-in-depth server count check in upstream nginx template"
```

---

### Task 4: Frontend — TabType 확장 및 UpstreamTab 생성

**Files:**
- Modify: `ui/src/components/proxy-host/types.ts:6`
- Create: `ui/src/components/proxy-host/tabs/UpstreamTab.tsx`

- [ ] **Step 1: Add 'upstream' to TabType**

In `ui/src/components/proxy-host/types.ts`, update line 6:

```typescript
export type TabType = 'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection' | 'upstream'
```

- [ ] **Step 2: Create UpstreamTab component**

Create `ui/src/components/proxy-host/tabs/UpstreamTab.tsx`. This is a refactored version of the existing `UpstreamPanel.tsx`, converted from a modal to a tab content component, with i18n and project styling applied.

```tsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { getUpstream, updateUpstream, deleteUpstream, getUpstreamHealth } from '../../../api/security';
import type { CreateUpstreamRequest } from '../../../types/security';

interface UpstreamTabProps {
  hostId: string;
}

export function UpstreamTabContent({ hostId }: UpstreamTabProps) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const [showAddServer, setShowAddServer] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);

  const { data: upstream, isLoading } = useQuery({
    queryKey: ['upstream', hostId],
    queryFn: () => getUpstream(hostId),
  });

  const { data: health } = useQuery({
    queryKey: ['upstream-health', upstream?.id],
    queryFn: () => getUpstreamHealth(upstream!.id),
    enabled: !!upstream?.id && !!upstream?.servers?.length && upstream?.health_check_enabled,
    refetchInterval: 30000,
  });

  const [form, setForm] = useState<CreateUpstreamRequest>({
    name: '',
    load_balance: 'round_robin',
    health_check_enabled: false,
    health_check_interval: 30,
    health_check_timeout: 5,
    health_check_path: '/',
    health_check_expected_status: 200,
    keepalive: 32,
    servers: [],
  });

  const [newServer, setNewServer] = useState({
    address: '',
    port: 80,
    weight: 1,
    max_fails: 3,
    fail_timeout: 30,
    is_backup: false,
  });

  // Sync form with upstream data on load
  useEffect(() => {
    if (upstream && upstream.servers?.length > 0) {
      setForm({
        name: upstream.name || '',
        load_balance: upstream.load_balance || 'round_robin',
        health_check_enabled: upstream.health_check_enabled,
        health_check_interval: upstream.health_check_interval || 30,
        health_check_timeout: upstream.health_check_timeout || 5,
        health_check_path: upstream.health_check_path || '/',
        health_check_expected_status: upstream.health_check_expected_status || 200,
        keepalive: upstream.keepalive || 32,
        servers: upstream.servers?.map(s => ({
          address: s.address,
          port: s.port,
          weight: s.weight,
          max_fails: s.max_fails,
          fail_timeout: s.fail_timeout,
          is_backup: s.is_backup,
          is_down: s.is_down,
        })) || [],
      });
      setHasChanges(false);
    }
  }, [upstream]);

  const saveMutation = useMutation({
    mutationFn: (data: CreateUpstreamRequest) => updateUpstream(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upstream', hostId] });
      setHasChanges(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteUpstream(hostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upstream', hostId] });
      setForm({ name: '', load_balance: 'round_robin', health_check_enabled: false, health_check_interval: 30, health_check_timeout: 5, health_check_path: '/', health_check_expected_status: 200, keepalive: 32, servers: [] });
      setHasChanges(false);
    },
  });

  const updateForm = (updates: Partial<CreateUpstreamRequest>) => {
    setForm(prev => ({ ...prev, ...updates }));
    setHasChanges(true);
  };

  const handleAddServer = () => {
    if (!newServer.address) return;
    updateForm({ servers: [...(form.servers || []), newServer] });
    setNewServer({ address: '', port: 80, weight: 1, max_fails: 3, fail_timeout: 30, is_backup: false });
    setShowAddServer(false);
  };

  const handleRemoveServer = (index: number) => {
    updateForm({ servers: form.servers?.filter((_, i) => i !== index) });
  };

  const handleSave = () => {
    if (!form.servers?.length) return;
    saveMutation.mutate(form);
  };

  const handleDelete = () => {
    if (window.confirm(t('upstream.deleteConfirm'))) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return <div className="p-6 text-center text-slate-400">{t('common:loading', 'Loading...')}</div>;
  }

  const hasServers = (form.servers?.length || 0) > 0;
  const hasExistingUpstream = upstream && upstream.servers?.length > 0;

  return (
    <div className="p-6 space-y-6">
      {/* Description */}
      <p className="text-sm text-slate-500 dark:text-slate-400">{t('upstream.description')}</p>

      {/* Health Status */}
      {health && hasExistingUpstream && (
        <div className={`p-3 rounded-lg ${health.is_healthy ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800' : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'}`}>
          <div className="flex items-center justify-between">
            <span className={`font-medium text-sm ${health.is_healthy ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}>
              {health.is_healthy ? t('upstream.healthy') : t('upstream.unhealthy')}
            </span>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {health.healthy_count} / {health.healthy_count + health.unhealthy_count} {t('upstream.serversUp')}
            </span>
          </div>
        </div>
      )}

      {/* Load Balance & Name */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('upstream.loadBalance')}</label>
          <select
            value={form.load_balance}
            onChange={e => updateForm({ load_balance: e.target.value })}
            className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="round_robin">{t('upstream.methods.roundRobin')}</option>
            <option value="least_conn">{t('upstream.methods.leastConn')}</option>
            <option value="ip_hash">{t('upstream.methods.ipHash')}</option>
            <option value="random">{t('upstream.methods.random')}</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('upstream.keepalive')}</label>
          <input
            type="number"
            value={form.keepalive || 32}
            onChange={e => updateForm({ keepalive: parseInt(e.target.value) || 32 })}
            className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            min={0}
          />
        </div>
      </div>

      {/* Backend Servers */}
      <div className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/50 border-b border-slate-200 dark:border-slate-700">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('upstream.backendServers')}</h4>
          <button type="button" onClick={() => setShowAddServer(true)}
            className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 font-medium">
            + {t('upstream.addServer')}
          </button>
        </div>

        {showAddServer && (
          <div className="p-3 border-b border-slate-200 dark:border-slate-700 bg-primary-50 dark:bg-primary-900/10 space-y-3">
            <div className="grid grid-cols-4 gap-2">
              <div className="col-span-2">
                <input type="text" value={newServer.address} onChange={e => setNewServer({ ...newServer, address: e.target.value })}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                  placeholder={t('upstream.addressPlaceholder')} />
              </div>
              <div>
                <input type="number" value={newServer.port} onChange={e => setNewServer({ ...newServer, port: parseInt(e.target.value) || 80 })}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                  placeholder={t('upstream.port')} min={1} max={65535} />
              </div>
              <div>
                <input type="number" value={newServer.weight} onChange={e => setNewServer({ ...newServer, weight: parseInt(e.target.value) || 1 })}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                  placeholder={t('upstream.weight')} min={1} />
              </div>
            </div>
            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={newServer.is_backup} onChange={e => setNewServer({ ...newServer, is_backup: e.target.checked })}
                  className="rounded border-slate-300 text-primary-600 focus:ring-primary-500" />
                <span className="text-sm text-slate-600 dark:text-slate-400">{t('upstream.backupServer')}</span>
              </label>
              <div className="flex gap-2">
                <button type="button" onClick={() => setShowAddServer(false)}
                  className="px-3 py-1.5 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200">
                  {t('common:buttons.cancel', 'Cancel')}
                </button>
                <button type="button" onClick={handleAddServer} disabled={!newServer.address}
                  className="px-3 py-1.5 text-sm bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50">
                  {t('upstream.addServer')}
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="divide-y divide-slate-200 dark:divide-slate-700">
          {!hasServers ? (
            <p className="p-4 text-center text-sm text-slate-400">{t('upstream.noServers')}</p>
          ) : (
            form.servers?.map((server, index) => {
              const healthStatus = health?.servers?.find(s => s.address === server.address && s.port === server.port);
              return (
                <div key={index} className="p-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {healthStatus && (
                      <span className={`w-2 h-2 rounded-full shrink-0 ${healthStatus.is_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                    )}
                    <span className="font-mono text-sm text-slate-700 dark:text-slate-300">{server.address}:{server.port}</span>
                    <span className="text-xs text-slate-400">w:{server.weight}</span>
                    {server.is_backup && <span className="px-1.5 py-0.5 text-xs bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300 rounded">{t('upstream.backup')}</span>}
                    {server.is_down && <span className="px-1.5 py-0.5 text-xs bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300 rounded">down</span>}
                  </div>
                  <button type="button" onClick={() => handleRemoveServer(index)}
                    className="text-sm text-red-500 hover:text-red-700">{t('common:buttons.delete', 'Delete')}</button>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Health Check */}
      <div className="border border-slate-200 dark:border-slate-700 rounded-lg p-4 space-y-3">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={form.health_check_enabled || false}
            onChange={e => updateForm({ health_check_enabled: e.target.checked })}
            className="rounded border-slate-300 text-primary-600 focus:ring-primary-500" />
          <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('upstream.enableHealthCheck')}</span>
          <span className="text-xs text-amber-500">({t('upstream.healthCheckNote')})</span>
        </label>

        {form.health_check_enabled && (
          <div className="grid grid-cols-2 gap-4 pt-2">
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('upstream.checkInterval')}</label>
              <input type="number" value={form.health_check_interval || 30}
                onChange={e => updateForm({ health_check_interval: parseInt(e.target.value) || 30 })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm" min={5} />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('upstream.checkTimeout')}</label>
              <input type="number" value={form.health_check_timeout || 5}
                onChange={e => updateForm({ health_check_timeout: parseInt(e.target.value) || 5 })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm" min={1} />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('upstream.checkPath')}</label>
              <input type="text" value={form.health_check_path || '/'}
                onChange={e => updateForm({ health_check_path: e.target.value })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm" placeholder="/health" />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('upstream.expectedStatus')}</label>
              <input type="number" value={form.health_check_expected_status || 200}
                onChange={e => updateForm({ health_check_expected_status: parseInt(e.target.value) || 200 })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm" />
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between pt-2">
        <div>
          {hasExistingUpstream && (
            <button type="button" onClick={handleDelete} disabled={deleteMutation.isPending}
              className="px-4 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors">
              {t('upstream.deleteUpstream')}
            </button>
          )}
        </div>
        <button type="button" onClick={handleSave} disabled={!hasServers || !hasChanges || saveMutation.isPending}
          className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white text-sm disabled:opacity-50">
          {saveMutation.isPending ? t('upstream.saving') : t('upstream.saveUpstream')}
        </button>
      </div>

      {saveMutation.isError && (
        <p className="text-sm text-red-500">{t('upstream.saveError')}: {(saveMutation.error as Error).message}</p>
      )}
      {saveMutation.isSuccess && !hasChanges && (
        <p className="text-sm text-green-500">{t('upstream.saveSuccess')}</p>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/components/proxy-host/types.ts ui/src/components/proxy-host/tabs/UpstreamTab.tsx
git commit -m "feat: create UpstreamTab component for proxy host form"
```

---

### Task 5: Frontend — ProxyHostForm에 upstream 탭 연결

**Files:**
- Modify: `ui/src/components/proxy-host/ProxyHostForm.tsx`

- [ ] **Step 1: Add import and tab definition**

Add import at the top (after other tab imports):

```typescript
import { UpstreamTabContent } from './tabs/UpstreamTab'
```

Update the `tabs` array (around line 103). Add upstream tab, but only for editing:

```typescript
  const tabs = [
    { id: 'basic' as TabType, label: t('form.tabs.basic'), icon: '🌐' },
    { id: 'ssl' as TabType, label: t('form.tabs.ssl'), icon: '🔒' },
    { id: 'security' as TabType, label: t('form.tabs.security'), icon: '🛡️' },
    { id: 'protection' as TabType, label: t('form.tabs.protection'), icon: '🚫' },
    { id: 'performance' as TabType, label: t('form.tabs.performance'), icon: '⚡' },
    ...(isEditing ? [{ id: 'upstream' as TabType, label: t('form.tabs.upstream'), icon: '⚖️' }] : []),
    { id: 'advanced' as TabType, label: t('form.tabs.advanced'), icon: '⚙️' },
  ]
```

- [ ] **Step 2: Add upstream tab content rendering**

Find the tab content rendering section in the JSX (where `{activeTab === 'basic' && ...}` etc. are). Add the upstream tab content:

```tsx
          {activeTab === 'upstream' && isEditing && host && (
            <UpstreamTabContent hostId={host.id} />
          )}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/components/proxy-host/ProxyHostForm.tsx
git commit -m "feat: integrate upstream tab into proxy host form"
```

---

### Task 6: i18n — upstream 번역 추가

**Files:**
- Modify: `ui/src/i18n/locales/ko/proxyHost.json`
- Modify: `ui/src/i18n/locales/en/proxyHost.json`

- [ ] **Step 1: Add Korean translations**

In the `form.tabs` section, add:

```json
"upstream": "로드밸런싱"
```

Add new `upstream` section at root level:

```json
"upstream": {
  "description": "여러 백엔드 서버에 트래픽을 분산하여 로드밸런싱과 고가용성을 구현합니다.",
  "loadBalance": "분배 방식",
  "methods": {
    "roundRobin": "라운드 로빈 (순차 분배)",
    "leastConn": "최소 연결 (가장 적은 연결 우선)",
    "ipHash": "IP 해시 (세션 유지)",
    "random": "랜덤"
  },
  "keepalive": "Keepalive 연결 수",
  "backendServers": "백엔드 서버",
  "addServer": "서버 추가",
  "noServers": "등록된 서버가 없습니다. 서버를 추가하면 로드밸런싱이 활성화됩니다.",
  "addressPlaceholder": "192.168.1.10 또는 호스트명",
  "port": "포트",
  "weight": "가중치",
  "backupServer": "백업 서버",
  "backup": "백업",
  "enableHealthCheck": "헬스체크 활성화",
  "healthCheckNote": "설정 저장만 가능, 자동 체크 미구현",
  "checkInterval": "체크 간격 (초)",
  "checkTimeout": "타임아웃 (초)",
  "checkPath": "체크 경로",
  "expectedStatus": "예상 상태코드",
  "healthy": "정상",
  "unhealthy": "비정상",
  "serversUp": "서버 가동 중",
  "saveUpstream": "저장",
  "saving": "저장 중...",
  "deleteUpstream": "업스트림 삭제",
  "deleteConfirm": "업스트림 설정을 삭제하시겠습니까? 단일 서버 모드로 전환됩니다.",
  "saveError": "저장 실패",
  "saveSuccess": "업스트림 설정이 저장되었습니다."
}
```

- [ ] **Step 2: Add English translations**

In the `form.tabs` section, add:

```json
"upstream": "Load Balancing"
```

Add new `upstream` section at root level:

```json
"upstream": {
  "description": "Distribute traffic across multiple backend servers for load balancing and high availability.",
  "loadBalance": "Method",
  "methods": {
    "roundRobin": "Round Robin (sequential)",
    "leastConn": "Least Connections",
    "ipHash": "IP Hash (session persistence)",
    "random": "Random"
  },
  "keepalive": "Keepalive Connections",
  "backendServers": "Backend Servers",
  "addServer": "Add Server",
  "noServers": "No servers configured. Add servers to enable load balancing.",
  "addressPlaceholder": "192.168.1.10 or hostname",
  "port": "Port",
  "weight": "Weight",
  "backupServer": "Backup server",
  "backup": "backup",
  "enableHealthCheck": "Enable Health Check",
  "healthCheckNote": "config only, auto-check not yet implemented",
  "checkInterval": "Check Interval (sec)",
  "checkTimeout": "Timeout (sec)",
  "checkPath": "Check Path",
  "expectedStatus": "Expected Status",
  "healthy": "Healthy",
  "unhealthy": "Unhealthy",
  "serversUp": "servers up",
  "saveUpstream": "Save",
  "saving": "Saving...",
  "deleteUpstream": "Delete Upstream",
  "deleteConfirm": "Delete upstream configuration? This will switch back to single server mode.",
  "saveError": "Save failed",
  "saveSuccess": "Upstream configuration saved."
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/i18n/locales/ko/proxyHost.json ui/src/i18n/locales/en/proxyHost.json
git commit -m "feat: add upstream/load balancing i18n translations"
```

---

### Task 7: Build, Test, and Documentation

- [ ] **Step 1: Build API**

```bash
sudo docker compose -f docker-compose.dev.yml build api
```

Expected: Build succeeds.

- [ ] **Step 2: Build UI**

```bash
sudo docker compose -f docker-compose.dev.yml build ui
```

Expected: Build succeeds.

- [ ] **Step 3: Deploy locally**

```bash
sudo docker compose -f docker-compose.dev.yml up -d api ui
```

- [ ] **Step 4: Test upstream API with nginx reload**

```bash
# Create test session, then:
# 1. Upsert upstream with servers
# 2. Verify nginx config was regenerated (check logs for reload)
# 3. Delete upstream
# 4. Verify nginx config was regenerated again
```

- [ ] **Step 5: Test name validation**

```bash
# Try creating upstream with invalid name (special characters)
# Should return error
```

- [ ] **Step 6: Run E2E tests**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
sudo docker compose -f docker-compose.e2e-test.yml up -d api
cd test/e2e && npx playwright test
```

- [ ] **Step 7: Update ARCHITECTURE.md**

Add upstream tab to the frontend routes section and note the nginx reload fix.

- [ ] **Step 8: Comment on GitHub issue #95**

```bash
gh issue comment 95 --body "v2.8.1에서 수정되었습니다. 프록시 호스트 편집 시 '로드밸런싱' 탭에서 upstream 서버를 설정할 수 있습니다."
```

- [ ] **Step 9: Commit documentation**

```bash
git add ARCHITECTURE.md
git commit -m "docs: update ARCHITECTURE.md with upstream GUI integration"
```
