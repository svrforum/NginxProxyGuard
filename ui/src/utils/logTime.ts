/** A log time as the logs show it: dated in the UI language, on a 24-hour clock (#373). */
export function formatLogTime(value: string | number | Date, language: string): string {
  return new Date(value).toLocaleString(language, { hourCycle: 'h23' });
}
