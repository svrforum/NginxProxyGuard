/**
 * Joins a host and a port the way a URL needs it: an IPv6 literal goes in
 * brackets, so 2001:db8::1 on port 80 reads "[2001:db8::1]:80" rather than the
 * ambiguous "2001:db8::1:80". The API stores forward hosts without brackets
 * (#314); a value that already has them, e.g. one saved by an older version or
 * one being typed into the form, is left as it is.
 */
export function formatHostPort(host: string, port: number | string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]:${port}` : `${host}:${port}`;
}
