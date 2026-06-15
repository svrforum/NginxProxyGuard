import { ReactNode } from 'react';

/**
 * Shared UI primitives for the refined entity-list design language
 * (cards, icon-button actions, status pills, icon empty states).
 * Used across Redirects, Certificates, Access Lists, WAF lists, etc. so the
 * whole app shares one consistent, scannable list aesthetic.
 */

type IconProps = { className?: string };
const ICON = 'h-4 w-4';

export function PencilIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
    </svg>
  );
}
export function TrashIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
    </svg>
  );
}
export function PlusIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
    </svg>
  );
}
/** Chevron pointing right; rotate-90 when expanded for a disclosure. */
export function ChevronRightIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.2} d="M9 5l7 7-7 7" />
    </svg>
  );
}
export function XIcon({ className = 'h-3 w-3' }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}
export function DownloadIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
    </svg>
  );
}
export function RenewIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  );
}
export function EyeIcon({ className = ICON }: IconProps) {
  return (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
    </svg>
  );
}

interface IconButtonProps {
  onClick?: (e: React.MouseEvent) => void;
  title: string;
  disabled?: boolean;
  variant?: 'default' | 'danger';
  children: ReactNode;
}

/** Subtle, hover-tinted icon button for row actions. */
export function IconButton({ onClick, title, disabled, variant = 'default', children }: IconButtonProps) {
  const tint =
    variant === 'danger'
      ? 'hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20 dark:hover:text-red-400'
      : 'hover:bg-slate-100 hover:text-indigo-600 dark:hover:bg-slate-700/60 dark:hover:text-indigo-400';
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={title}
      disabled={disabled}
      className={`rounded-lg p-2 text-slate-400 transition-colors disabled:opacity-50 ${tint}`}
    >
      {children}
    </button>
  );
}

/** Primary "add" button with a leading plus icon. */
export function AddButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-slate-900"
    >
      <PlusIcon />
      {children}
    </button>
  );
}

/** Centered empty state: tinted icon square + muted text in a dashed-border box. */
export function EmptyState({ icon, children }: { icon?: ReactNode; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/30 px-6 py-14 text-center">
      {icon && (
        <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-400">
          {icon}
        </div>
      )}
      <p className="text-sm text-slate-500 dark:text-slate-400">{children}</p>
    </div>
  );
}

/** Rounded status pill with a leading dot. */
export function StatusPill({ active, children }: { active: boolean; children?: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
        active
          ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300'
          : 'bg-slate-100 text-slate-500 dark:bg-slate-700/50 dark:text-slate-400'
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${active ? 'bg-emerald-500' : 'bg-slate-400'}`} />
      {children}
    </span>
  );
}

/** Rounded entity card wrapper with consistent border/hover. */
export function EntityCard({ active, children }: { active?: boolean; children: ReactNode }) {
  return (
    <div
      className={`group rounded-xl border bg-white dark:bg-slate-800 transition-all ${
        active
          ? 'border-indigo-300 dark:border-indigo-700 shadow-sm'
          : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600'
      }`}
    >
      {children}
    </div>
  );
}
