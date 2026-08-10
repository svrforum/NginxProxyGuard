#!/usr/bin/env bash
# Pre-commit PII scan for a PUBLIC repository.
#
# Run before every commit: scripts/pii-scan.sh
# Add --range origin/main..HEAD to scan a whole push instead of the staged diff.
#
# The .git/hooks/pre-commit hook is the last-resort backstop and only blocks
# email domains. Domains, server IPs, real names and contact details are caught
# here or not at all. A finding is a stop: replace the value and re-run.
#
# Allowed placeholders: 192.0.2.x / 198.51.100.x / 203.0.113.x (RFC5737),
# RFC1918 ranges in generic form, 127.0.0.1, user@example.com, *.example.com.
set -uo pipefail

RANGE=""
if [[ "${1:-}" == "--range" && -n "${2:-}" ]]; then RANGE="$2"; fi

if [[ -n "$RANGE" ]]; then
  diff_cmd() { git diff "$RANGE"; }
  msg_cmd()  { git log "$RANGE" --format='%B'; }
  who_cmd()  { git log "$RANGE" --format='%an <%ae>|%cn <%ce>' | sort -u; }
  echo "== scanning range $RANGE (diff + commit messages + authors)"
else
  diff_cmd() { git diff --cached; }
  msg_cmd()  { :; }
  who_cmd()  { git config user.email; }
  echo "== scanning staged changes"
fi

fail=0
report() { printf '  %s %s\n' "$1" "$2"; }

# 1. Commit identity must be the project's GitHub noreply address.
ident="$(who_cmd)"
if grep -qivE 'users\.noreply\.github\.com' <<<"$ident"; then
  report "FAIL" "identity is not a GitHub noreply address:"; sed 's/^/    /' <<<"$ident"; fail=1
else
  report "ok  " "commit identity"
fi

# 2. Email addresses outside the allowlist.
hits="$( { diff_cmd; msg_cmd; } | grep -inE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' \
        | grep -ivE 'example\.(com|org|net)|users\.noreply\.github|npg-test\.example|support@github\.com' || true)"
# support@github.com is Dependabot's Signed-off-by line on merged upstream
# commits — a bot address, not a person's.
if [[ -n "$hits" ]]; then report "FAIL" "email address:"; sed 's/^/    /' <<<"$hits" | head -5; fail=1
else report "ok  " "no personal email"; fi

# 3. IPv4 outside the documentation and private ranges. Private ranges pass the
#    regex but are still worth eyeballing: a generic 192.168.x.x reads as an
#    example, a specific host address is somebody's actual server.
ips="$( { diff_cmd; msg_cmd; } | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
       | grep -vE '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1$|0\.0\.0\.0$)' | sort -u || true)"
if [[ -n "$ips" ]]; then report "WARN" "IPv4 to eyeball (private ranges are ok in generic form):"; sed 's/^/    /' <<<"$ips"
else report "ok  " "no non-documentation IPv4"; fi

# 4. Real domains, names and contact details. Extend this list as the project
#    learns new ones; keep specific blocked tokens out of tracked files.
pat="${NPG_PII_PATTERN:-}"
if [[ -n "$pat" ]]; then
  hits="$( { diff_cmd; msg_cmd; } | grep -inE "$pat" || true)"
  if [[ -n "$hits" ]]; then report "FAIL" "operating domain or personal identifier:"; sed 's/^/    /' <<<"$hits" | head -5; fail=1
  else report "ok  " "no operating domain or personal identifier"; fi
else
  report "note" "set NPG_PII_PATTERN to also grep your own domains and names"
fi

# 5. Internal planning docs must stay untracked.
tracked="$(git ls-files | grep -E 'docs/superpowers|PLAN_DB_PERFORMANCE|ARCHITECTURE\.md|MIGRATION-v2' || true)"
if [[ -n "$tracked" ]]; then report "FAIL" "gitignored planning doc is tracked:"; sed 's/^/    /' <<<"$tracked"; fail=1
else report "ok  " "planning docs untracked"; fi

echo
if [[ $fail -ne 0 ]]; then echo "PII scan FAILED — fix the findings above before committing."; exit 1; fi
echo "PII scan passed."
