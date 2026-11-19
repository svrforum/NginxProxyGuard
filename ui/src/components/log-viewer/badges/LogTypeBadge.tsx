import type { LogType } from '../types';

interface LogTypeBadgeProps {
  type: LogType;
}

export function LogTypeBadge({ type }: LogTypeBadgeProps) {
  const colors: Record<LogType, string> = {
    access: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    error: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    modsec: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
    stream: 'bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-400',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[type]}`}>
      {type}
    </span>
  );
}
