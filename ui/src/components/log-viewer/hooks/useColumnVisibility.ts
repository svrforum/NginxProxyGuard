import { useCallback, useEffect, useState } from 'react';

export type AccessColumnKey =
  | 'time'
  | 'host'
  | 'ip'
  | 'country'
  | 'method'
  | 'uri'
  | 'status'
  | 'block'
  | 'size'
  | 'responseTime'
  | 'upstream'
  | 'userAgent';

export const ACCESS_COLUMN_ORDER: AccessColumnKey[] = [
  'time', 'host', 'ip', 'country', 'method', 'uri', 'status', 'block', 'size', 'responseTime', 'upstream', 'userAgent',
];

// Columns that cannot be hidden. `time` anchors the row visually and `uri` carries
// the primary content — removing either leaves a table that's hard to scan.
export const REQUIRED_ACCESS_COLUMNS: ReadonlySet<AccessColumnKey> = new Set(['time', 'uri']);

// Columns that are part of the default "everything on" set. User-Agent is long and
// optional — hidden out of the box so users can opt in via the column chooser.
const DEFAULT_VISIBLE_ACCESS_COLUMNS: ReadonlySet<AccessColumnKey> = new Set(
  ACCESS_COLUMN_ORDER.filter((k) => k !== 'userAgent'),
);

const STORAGE_KEY_PREFIX = 'npg_log_columns_';

function storageKey(logType: string): string {
  return `${STORAGE_KEY_PREFIX}${logType}`;
}

function loadVisibility(
  logType: string,
  allColumns: readonly AccessColumnKey[],
  defaults: ReadonlySet<AccessColumnKey>,
): Set<AccessColumnKey> {
  try {
    const raw = localStorage.getItem(storageKey(logType));
    if (!raw) return new Set(defaults);
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set(defaults);
    const valid = parsed.filter((k): k is AccessColumnKey =>
      typeof k === 'string' && (allColumns as readonly string[]).includes(k),
    );
    // Required columns are always visible regardless of what's persisted.
    REQUIRED_ACCESS_COLUMNS.forEach((k) => valid.push(k));
    return new Set(valid);
  } catch {
    return new Set(defaults);
  }
}

export function useAccessColumnVisibility() {
  const [visible, setVisible] = useState<Set<AccessColumnKey>>(() =>
    loadVisibility('access', ACCESS_COLUMN_ORDER, DEFAULT_VISIBLE_ACCESS_COLUMNS),
  );

  useEffect(() => {
    try {
      localStorage.setItem(storageKey('access'), JSON.stringify([...visible]));
    } catch {
      // localStorage may be unavailable (e.g. private mode); the toggle still works
      // for the current session, just not persisted. No user-visible error needed.
    }
  }, [visible]);

  const toggle = useCallback((key: AccessColumnKey) => {
    if (REQUIRED_ACCESS_COLUMNS.has(key)) return;
    setVisible((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const reset = useCallback(() => {
    setVisible(new Set(DEFAULT_VISIBLE_ACCESS_COLUMNS));
  }, []);

  return { visible, toggle, reset };
}
