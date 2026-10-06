/**
 * The custom allowed-agents syntax (#313), mirrored from the server parser in
 * api/internal/model/bot_filter_scope.go so the form can preview and check a
 * list before saving. The server stays the authority: it validates every
 * changed value and the nginx renderer drops lines it cannot use.
 *
 *   GoodBot                              exempt on the whole host
 *   okhttp @ /api                        exempt only under /api
 *   python-requests @ /webhook /hooks    exempt under either path
 */

export const MAX_SCOPED_ALLOWED_AGENTS = 20
export const MAX_ALLOWED_AGENT_PATHS = 10
const MAX_PATH_LENGTH = 255

/** Why a line that names paths cannot be used. `path`/`char`/`max` feed the message. */
export type AllowedAgentIssue =
  | { code: 'gluedAt' | 'noAgent' | 'noPath' }
  | { code: 'tooManyPaths' | 'tooManyScoped'; max: number }
  | { code: 'pathNoSlash' | 'pathPercent' | 'pathDoubleSlash' | 'pathQuery' | 'pathDotSegment' | 'pathNotAscii'; path: string }
  | { code: 'pathChar'; path: string; char: string }
  | { code: 'pathTooLong'; path: string; max: number }

export interface AllowedAgentLine {
  /** 1-based line number in the field, blank and comment lines included. */
  line: number
  text: string
  kind: 'site' | 'scoped' | 'invalid'
  agent: string
  paths: string[]
  issue?: AllowedAgentIssue
}

// Only spaces and tabs separate, exactly like the server.
const SCOPE_SEP = /(?:^|[ \t])@(?:[ \t]|$)/
const GLUED_SEP = /(?:^|[ \t])@\/|[^ \t]@[ \t]+\//

function pathIssue(path: string): AllowedAgentIssue | undefined {
  if (!path.startsWith('/')) return { code: 'pathNoSlash', path }
  if (path.includes('%')) return { code: 'pathPercent', path }
  if (path.includes('//')) return { code: 'pathDoubleSlash', path }
  if (/[?#]/.test(path)) return { code: 'pathQuery', path }
  if (path.split('/').some((seg) => seg !== '' && /^\.+$/.test(seg))) return { code: 'pathDotSegment', path }
  const bad = path.match(/["'\\`;{}$|&<>]/)
  if (bad) return { code: 'pathChar', path, char: bad[0] }
  if (!/^[\x21-\x7e]+$/.test(path)) return { code: 'pathNotAscii', path }
  if (path.length > MAX_PATH_LENGTH) return { code: 'pathTooLong', path, max: MAX_PATH_LENGTH }
  return undefined
}

/** Splits one trimmed line; `paths` is empty for a line that covers the whole host. */
function splitLine(text: string): { agent: string; paths: string[]; issue?: AllowedAgentIssue } {
  const sep = SCOPE_SEP.exec(text)
  if (!sep) return { agent: text, paths: [], issue: GLUED_SEP.test(text) ? { code: 'gluedAt' } : undefined }
  const agent = text.slice(0, sep.index).trim()
  const paths = text.slice(sep.index + sep[0].length).split(/[ \t]+/).filter((p) => p !== '')
  if (agent === '') return { agent, paths, issue: { code: 'noAgent' } }
  if (paths.length === 0) return { agent, paths, issue: { code: 'noPath' } }
  if (paths.length > MAX_ALLOWED_AGENT_PATHS) {
    return { agent, paths, issue: { code: 'tooManyPaths', max: MAX_ALLOWED_AGENT_PATHS } }
  }
  for (const p of paths) {
    const issue = pathIssue(p)
    if (issue) return { agent, paths, issue }
  }
  // "/" covers the whole host, which makes the line an ordinary one.
  return { agent, paths: paths.includes('/') ? [] : paths }
}

/** Reads every non-blank, non-comment line of a custom allowed-agents value. */
export function parseAllowedAgents(raw: string): AllowedAgentLine[] {
  const out: AllowedAgentLine[] = []
  let scoped = 0
  raw.split('\n').forEach((rawLine, i) => {
    const text = rawLine.trim()
    if (text === '' || text.startsWith('#')) return
    const { agent, paths, issue: lineIssue } = splitLine(text)
    const issue: AllowedAgentIssue | undefined = lineIssue
      ?? (paths.length > 0 && scoped === MAX_SCOPED_ALLOWED_AGENTS
        ? { code: 'tooManyScoped', max: MAX_SCOPED_ALLOWED_AGENTS }
        : undefined)
    if (issue) {
      out.push({ line: i + 1, text, kind: 'invalid', agent: text, paths: [], issue })
      return
    }
    if (paths.length > 0) scoped++
    out.push({ line: i + 1, text, kind: paths.length > 0 ? 'scoped' : 'site', agent, paths })
  })
  return out
}

type Translate = (key: string, options?: Record<string, unknown>) => string

/**
 * The reason for an invalid line. `t` must be the `proxyHost` namespace, so
 * both the host form and the global settings page can use it.
 */
export function describeAllowedAgentIssue(issue: AllowedAgentIssue, t: Translate): string {
  return t(`form.security.botFilter.allowedIssues.${issue.code}`, { ...issue })
}

/**
 * The first line the server would refuse, with its reason, or null when the
 * value may be saved. Like the server, only a value that differs from the
 * stored one is checked: an old line saved before this syntax existed must not
 * block the rest of a save.
 */
export function allowedAgentsSaveIssue(
  value: string,
  stored: string,
  t: Translate,
): { line: number; reason: string } | null {
  if (value === stored) return null
  const bad = parseAllowedAgents(value).find((l) => l.kind === 'invalid')
  return bad?.issue ? { line: bad.line, reason: describeAllowedAgentIssue(bad.issue, t) } : null
}
