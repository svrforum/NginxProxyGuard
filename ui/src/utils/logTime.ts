// Every part named: with hourCycle alone, Korean writes the time as "13시 5분 1초".
const LOG_TIME: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'numeric',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
};

/** A log time as the logs show it: dated in the UI language, on a 24-hour clock (#373). */
export function formatLogTime(value: string | number | Date, language: string): string {
  return new Date(value).toLocaleString(language, LOG_TIME);
}
