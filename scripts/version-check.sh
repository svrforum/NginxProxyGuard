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
declare -A got
got[constants.go]=$(grep -oP 'AppVersion = "\K[^"]+' api/internal/config/constants.go)
got[package.json]=$(python3 -c "import json;print(json.load(open('ui/package.json'))['version'])")
got[package-lock.json]=$(python3 -c "import json;print(json.load(open('ui/package-lock.json'))['version'])")
got[swagger.yaml]=$(grep -m1 -oP '^  version: \K.*' api/internal/handler/swagger.yaml)

ref="${want:-${got[constants.go]}}"
fail=0
for k in constants.go package.json package-lock.json swagger.yaml; do
  if [[ "${got[$k]}" == "$ref" ]]; then printf '  ok   %-20s %s\n' "$k" "${got[$k]}"
  else printf '  FAIL %-20s %s (expected %s)\n' "$k" "${got[$k]}" "$ref"; fail=1; fi
done

# The lock's nested self-reference is easy to miss and breaks the next npm bump.
nested=$(python3 -c "
import json; d=json.load(open('ui/package-lock.json'))
print(d.get('packages',{}).get('',{}).get('version','(absent)'))")
if [[ "$nested" == "$ref" ]]; then printf '  ok   %-20s %s\n' 'lock packages[""]' "$nested"
else printf '  FAIL %-20s %s (expected %s)\n' 'lock packages[""]' "$nested" "$ref"; fail=1; fi

echo
[[ $fail -eq 0 ]] && { echo "versions agree on $ref"; exit 0; }
echo "version files disagree — fix them before tagging."; exit 1
