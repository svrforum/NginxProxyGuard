import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ACCESS_COLUMN_ORDER,
  REQUIRED_ACCESS_COLUMNS,
  type AccessColumnKey,
} from './hooks/useColumnVisibility';

interface ColumnChooserProps {
  visible: Set<AccessColumnKey>;
  onToggle: (key: AccessColumnKey) => void;
  onReset: () => void;
}

export function ColumnChooser({ visible, onToggle, onReset }: ColumnChooserProps) {
  const { t } = useTranslation('logs');
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handleClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const hiddenCount = ACCESS_COLUMN_ORDER.length - visible.size;

  return (
    <div ref={containerRef} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
          hiddenCount > 0
            ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300'
            : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
        }`}
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M4 6h16M4 12h10M4 18h6"
          />
        </svg>
        {t('table.columnChooser.button')}
        {hiddenCount > 0 && (
          <span className="px-1.5 py-0.5 bg-primary-600 text-white rounded-full text-xs">
            {visible.size}/{ACCESS_COLUMN_ORDER.length}
          </span>
        )}
      </button>

      {open && (
        <div
          className="absolute right-0 mt-2 w-64 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg z-30"
          role="dialog"
          aria-label={t('table.columnChooser.title')}
        >
          <div className="flex items-center justify-between px-4 py-2 border-b border-slate-200 dark:border-slate-700">
            <span className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400">
              {t('table.columnChooser.title')}
            </span>
            <button
              onClick={onReset}
              className="text-xs text-primary-600 dark:text-primary-400 hover:underline"
            >
              {t('table.columnChooser.reset')}
            </button>
          </div>
          <ul className="py-1 max-h-80 overflow-y-auto">
            {ACCESS_COLUMN_ORDER.map((key) => {
              const required = REQUIRED_ACCESS_COLUMNS.has(key);
              const checked = visible.has(key);
              return (
                <li key={key}>
                  <label
                    className={`flex items-center gap-2 px-4 py-2 text-sm text-slate-700 dark:text-slate-200 ${
                      required
                        ? 'opacity-60 cursor-not-allowed'
                        : 'cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/50'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={required}
                      onChange={() => onToggle(key)}
                      className="rounded"
                    />
                    <span className="flex-1">{t(`table.columns.${key === 'uri' ? 'path' : key}`)}</span>
                    {required && (
                      <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase">
                        {t('table.columnChooser.required')}
                      </span>
                    )}
                  </label>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
