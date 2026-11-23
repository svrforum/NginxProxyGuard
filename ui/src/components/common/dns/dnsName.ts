import type { DNSEntryStatus } from '../../../types/dnsEntries';
import { isIPOrCIDR } from '../../proxy-host/tabs/security/priorityAllowEntries';
import { formatDateTime } from '../../../utils/dateTime';

// Domain names as the server takes them (#320; the server's copy
// is model.ValidateDNSName). The form checks first so the reason shows next to
// the row, but the server decides.

export type DnsNameErrorCode =
  | 'empty'
  | 'too_long'
  | 'label'
  | 'hyphen'
  | 'single_label'
  | 'tld'
  | 'looks_like_ip'
  | 'wildcard'
  | 'underscore'
  | 'url_or_port'
  | 'whitespace'
  | 'non_ascii'
  | 'internal_suffix';

export const DNS_NAME_ERROR_CODES: readonly string[] = [
  'empty',
  'too_long',
  'label',
  'hyphen',
  'single_label',
  'tld',
  'looks_like_ip',
  'wildcard',
  'underscore',
  'url_or_port',
  'whitespace',
  'non_ascii',
  'internal_suffix',
];

// Names that never resolve on the internet, matched on whole labels.
const INTERNAL_SUFFIXES = [
  'localhost',
  'local',
  'localdomain',
  'internal',
  'lan',
  'home',
  'home.arpa',
  'arpa',
  'invalid',
  'test',
  'onion',
  'corp',
  'intranet',
  'private',
];

/**
 * Trims, lower-cases ASCII letters and drops one trailing dot, like the
 * server's NormalizeDNSName. Only A-Z are lowered: toLowerCase() turns the
 * Kelvin sign (U+212A) into an ASCII "k", which would hide that the name is
 * not what was typed.
 */
export function normalizeDnsName(s: string): string {
  const n = s.trim().replace(/[A-Z]+/g, (letters) => letters.toLowerCase());
  return n.endsWith('.') ? n.slice(0, -1) : n;
}

/**
 * The first rule a normalized name breaks, in the server's order, or null.
 * Codes are the server's DNSNameError codes.
 */
export function checkDnsName(name: string): DnsNameErrorCode | null {
  if (name === '') return 'empty';
  const labels = name.split('.');
  const last = labels[labels.length - 1];
  if (name === 'all' || isIPOrCIDR(name) || /^[0-9.]*[0-9][0-9.]*$/.test(name) || /^[0-9]+$/.test(last)) {
    return 'looks_like_ip';
  }
  if (/[\s\p{Cc}]/u.test(name)) return 'whitespace';
  if (/[^ -~]/.test(name)) return 'non_ascii';
  if (name.includes('*')) return 'wildcard';
  if (name.includes('_')) return 'underscore';
  if (/[:/?#@[\]\\]/.test(name)) return 'url_or_port';
  if (name.length > 253) return 'too_long';
  for (const label of labels) {
    if (label.length < 1 || label.length > 63 || !/^[a-z0-9-]+$/.test(label)) return 'label';
    if (label.startsWith('-') || label.endsWith('-')) return 'hyphen';
  }
  if (labels.length < 2) return 'single_label';
  if (!/^[a-z]+$/.test(last) && !/^xn--[a-z0-9-]+$/.test(last)) return 'tld';
  for (const suffix of INTERNAL_SUFFIXES) {
    if (name === suffix || name.endsWith(`.${suffix}`)) return 'internal_suffix';
  }
  return null;
}

function labelCount(s: string): number {
  return normalizeDnsName(s).split('.').length;
}

export type AsciiName = { ascii: string } | { code: DnsNameErrorCode };

/**
 * The name to send for what the operator typed. The URL parser that turns a
 * non-ASCII name into its xn-- form also rewrites input silently
 * ("ü@evil.example" becomes "evil.example", "ex%41mple.com" becomes
 * "example.com", a soft hyphen disappears), so the raw text is checked first,
 * and the converted name must keep its label count and pass every rule again.
 */
export function toAsciiName(raw: string): AsciiName {
  const s = raw.trim();
  if (s === '') return { code: 'empty' };
  if (/[\s\p{Cc}\p{Cf}]/u.test(s)) return { code: 'whitespace' };
  if (s.includes('*')) return { code: 'wildcard' };
  if (s.includes('_')) return { code: 'underscore' };
  if (/[%:/?#@[\]\\]/.test(s)) return { code: 'url_or_port' };
  let host = s;
  if (/[^ -~]/.test(s)) {
    try {
      host = new URL(`http://${s}`).hostname;
    } catch {
      return { code: 'non_ascii' };
    }
    if (labelCount(host) !== labelCount(s)) return { code: 'non_ascii' };
  }
  const name = normalizeDnsName(host);
  const code = checkDnsName(name);
  return code ? { code } : { ascii: name };
}

export interface EntryClass {
  kind: 'all' | 'ip' | 'hostname' | 'invalid';
  code?: DnsNameErrorCode;
  /** hostname only: the name that is sent, and shown after saving. */
  ascii?: string;
}

/**
 * What one access-rule cell holds. `all` and IP/CIDR are tested first, as on the
 * server, so an address is never read as a name.
 */
export function classifyEntry(raw: string): EntryClass {
  const s = raw.trim();
  if (s === 'all') return { kind: 'all' };
  if (isIPOrCIDR(s)) return { kind: 'ip' };
  const result = toAsciiName(s);
  if ('code' in result) return { kind: 'invalid', code: result.code };
  return { kind: 'hostname', ascii: result.ascii };
}

/**
 * True while something about a name is still on its way: the first answer, an
 * addition waiting for its turn, addresses nginx has not loaded yet, or a
 * removal nginx still allows. The lists poll only then. While the feature is
 * switched off a name waits for nothing but such a removal.
 */
export function dnsNeedsPolling(statuses: ReadonlyArray<DNSEntryStatus | null | undefined>): boolean {
  return statuses.some(
    (s) =>
      !!s &&
      (s.revoke_pending ||
        (!s.disabled &&
          (s.status === 'pending' ||
            (s.pending_addresses ?? []).length > 0 ||
            (!s.applied && (s.addresses ?? []).length > 0)))),
  );
}

/** A timestamp in the UI's language, not the browser's. */
export function formatDnsTime(iso: string | null | undefined, lang: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return formatDateTime(d, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }, lang);
}

/** The i18n key suffix (familyState.<key>) of a family state; "unknown" when there is none. */
export function familyStateKey(state: string | undefined): string {
  return state || 'unknown';
}
