import i18n from '../i18n';

// Every time in the UI is on a 24-hour clock, dated in the UI language (#373, #399).
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

export const TIME: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit' };

export const HOUR_MINUTE: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' };

/** A date and time as the UI shows it: `parts` picks what to show, the clock is always 24-hour. */
export function formatDateTime(
  value: string | number | Date,
  parts: Intl.DateTimeFormatOptions = DATE_TIME,
  language: string = i18n.language,
): string {
  // eslint-disable-next-line no-restricted-syntax -- the one place that sets the clock
  return new Date(value).toLocaleString(language, { ...parts, hourCycle: 'h23' });
}
