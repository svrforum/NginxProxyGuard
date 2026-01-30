import { useState } from 'react';
import { useTranslation } from 'react-i18next';

interface MethodBadgeProps {
  method: string;
}

// Check if string contains control characters or non-printable bytes
function containsControlChars(str: string): boolean {
  // Match control characters (0x00-0x1F, 0x7F) or escape sequences like \x00
  return /[\x00-\x1F\x7F]|\\x[0-9a-fA-F]{2}/.test(str);
}

// Truncate and sanitize for display
function sanitizeMethod(str: string, maxLen = 12): string {
  // Replace control characters with visible representation
  const sanitized = str.replace(/[\x00-\x1F\x7F]/g, '·');
  if (sanitized.length > maxLen) {
    return sanitized.slice(0, maxLen) + '…';
  }
  return sanitized;
}

export function MethodBadge({ method }: MethodBadgeProps) {
  const { t } = useTranslation('logs');
  const [showRaw, setShowRaw] = useState(false);

  const colors: Record<string, string> = {
    GET: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    POST: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    PUT: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    DELETE: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    PATCH: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400',
    HEAD: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-400',
    OPTIONS: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-400',
  };

  const isBinary = containsControlChars(method);
  const isValidMethod = colors[method] !== undefined;

  // For binary/invalid methods, show warning style
  if (isBinary || (!isValidMethod && method.length > 10)) {
    return (
      <span className="relative group">
        <span
          className="px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 cursor-help flex items-center gap-1"
          title={t('method.binaryTooltip', { defaultValue: 'Click to view raw data' })}
          onClick={(e) => {
            e.stopPropagation();
            setShowRaw(!showRaw);
          }}
        >
          <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          {isBinary ? t('method.binary', { defaultValue: 'Binary' }) : sanitizeMethod(method)}
        </span>

        {/* Raw data popup */}
        {showRaw && (
          <div
            className="absolute z-50 left-0 top-full mt-1 p-2 bg-slate-800 text-slate-200 rounded-lg shadow-lg text-xs max-w-xs"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-slate-400">{t('method.rawData', { defaultValue: 'Raw Data' })}</span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(method);
                }}
                className="text-xs text-blue-400 hover:text-blue-300"
              >
                {t('method.copy', { defaultValue: 'Copy' })}
              </button>
            </div>
            <code className="block font-mono break-all whitespace-pre-wrap bg-slate-900 p-1.5 rounded max-h-32 overflow-auto">
              {method.split('').map((char, i) => {
                const code = char.charCodeAt(0);
                if (code < 32 || code === 127) {
                  return <span key={i} className="text-red-400">\\x{code.toString(16).padStart(2, '0')}</span>;
                }
                return char;
              })}
            </code>
          </div>
        )}
      </span>
    );
  }

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[method] || 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300'}`}>
      {method}
    </span>
  );
}
