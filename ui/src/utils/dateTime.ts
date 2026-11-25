import i18n from '../i18n';

// Every time in the UI is on a 24-hour clock (#373, #399). Korean dates follow
// the Korean format; English ones are written year first, because "11/18/2026"
// is a US order that reads as day/month almost everywhere else (#401).
// A format names each part it shows: with hourCycle alone, Korean writes the
// time as "13시 5분 1초".
export const DATE_TIME: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'numeric',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
};

export const DATE: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'numeric', day: 'numeric' };

export const TIME: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit' };

export const HOUR_MINUTE: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' };

/** A date and time as the UI shows it: `parts` picks what to show, the clock is always 24-hour. */
export function formatDateTime(
  value: string | number | Date,
  parts: Intl.DateTimeFormatOptions = DATE_TIME,
  language: string = i18n.language,
): string {
  const date = new Date(value);
  const options: Intl.DateTimeFormatOptions = { ...parts, hourCycle: 'h23' };
  const numericMonth = parts.month === 'numeric' || parts.month === '2-digit';
  if (numericMonth && language.toLowerCase().startsWith('en') && !Number.isNaN(date.getTime())) {
    return yearFirst(date, options);
  }
  return date.toLocaleString(language, options);
}

/** 2026-11-18 15:21:48, keeping only the parts `options` asks for. */
function yearFirst(date: Date, options: Intl.DateTimeFormatOptions): string {
  const p: Partial<Record<Intl.DateTimeFormatPartTypes, string>> = {};
  for (const part of new Intl.DateTimeFormat('en', options).formatToParts(date)) p[part.type] = part.value;
  const pad = (v?: string) => v?.padStart(2, '0');
  const day = [p.year, pad(p.month), pad(p.day)].filter(Boolean).join('-');
  const time = [pad(p.hour), pad(p.minute), pad(p.second)].filter(Boolean).join(':');
  return [day, time].filter(Boolean).join(' ');
}
