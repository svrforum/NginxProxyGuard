#!/usr/bin/env bash
# Verify every file that carries the release version agrees.
#
#   scripts/version-check.sh            # all four must match each other
#   scripts/version-check.sh 2.37.1     # ...and must equal this
#
# Exists because the list lived in prose and swagger.yaml was missed for two
# releases running. A stale version in the API spec is worse than cosmetic:
# it is the first thing a client author reads to decide whether the document
# describes the server they are talking to.
set -uo pipefail
cd "$(dirname "$0")/.."

want="${1:-}"

# --committed reads the files as HEAD has them, not as they sit on disk.
#
# This matters because the two can differ silently: a `git stash` around the
# release scan un-staged the bumps, the commit went out with the old numbers,
# and a working-tree check still said everything agreed. v2.37.1 shipped
# reporting itself as 2.37.0. Always run this against the commit before tagging.
src="disk"
read_file() { cat "$1"; }
if [[ "${1:-}" == "--committed" ]]; then
  src="HEAD"; want="${2:-}"
  read_file() { git show "HEAD:$1"; }
fi
echo "== reading from $src"

declare -A got
got[constants.go]=$(read_file api/internal/config/constants.go | grep -oP 'AppVersion = "\K[^"]+')
got[package.json]=$(read_file ui/package.json | python3 -c "import json,sys;print(json.load(sys.stdin)['version'])")
got[package-lock.json]=$(read_file ui/package-lock.json | python3 -c "import json,sys;print(json.load(sys.stdin)['version'])")
got[swagger.yaml]=$(read_file api/internal/handler/swagger.yaml | grep -m1 -oP '^  version: \K.*')

ref="${want:-${got[constants.go]}}"
fail=0
for k in constants.go package.json package-lock.json swagger.yaml; do
  if [[ "${got[$k]}" == "$ref" ]]; then printf '  ok   %-20s %s\n' "$k" "${got[$k]}"
  else printf '  FAIL %-20s %s (expected %s)\n' "$k" "${got[$k]}" "$ref"; fail=1; fi
done

# The lock's nested self-reference is easy to miss and breaks the next npm bump.
nested=$(read_file ui/package-lock.json | python3 -c "
import json,sys; d=json.load(sys.stdin)
print(d.get('packages',{}).get('',{}).get('version','(absent)'))")
if [[ "$nested" == "$ref" ]]; then printf '  ok   %-20s %s\n' 'lock packages[""]' "$nested"
else printf '  FAIL %-20s %s (expected %s)\n' 'lock packages[""]' "$nested" "$ref"; fail=1; fi

echo
[[ $fail -eq 0 ]] && { echo "versions agree on $ref"; exit 0; }
echo "version files disagree — fix them before tagging."; exit 1
