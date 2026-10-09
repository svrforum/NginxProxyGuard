#!/bin/sh
# Upgrade the rules NPG ships in modsec/custom-rules.conf on an existing
# install. docker-entrypoint.sh runs this on every start.
#
# Why: custom-rules.conf lives in the nginx volume and, unlike modsec-base.conf
# and crs-global.conf, is never refreshed from the image, because operators add
# their own rules to it. A fix to one of NPG's rules in it would reach fresh
# installs only. v2.60.1 changed three of them: the health-check (1000) and
# Socket.IO (1002) exemptions now decide on the normalized request path, and
# the WebSocket rule (1003) no longer switches the WAF off.
#
# OLD_DEFAULT is the file NPG shipped before (v1.0.1 through v2.60.0):
#   - CURRENT is byte-identical to it   -> it becomes NEW_DEFAULT
#   - otherwise, each NPG rule that differs between OLD_DEFAULT and NEW_DEFAULT:
#       still the old text (whitespace aside) -> replaced by the new rule
#       already the new text                  -> kept
#       edited locally                        -> kept, with a WARN
#     Every other line is kept byte for byte.
# A changed file keeps its owner and mode, is replaced atomically, and the
# previous version is kept once as custom-rules.conf.pre-v2.60.1. Once the
# rules are current, later starts change nothing and print nothing.
#
# usage: upgrade-custom-rules.sh CURRENT NEW_DEFAULT OLD_DEFAULT

set -eu

cur=$1 new=$2 old=$3
[ -f "$cur" ] && [ -f "$new" ] && [ -f "$old" ] || exit 0

tmp=$cur.npg-upgrade
backup=$cur.pre-v2.60.1
trap 'rm -f "$tmp"' EXIT
cp -p "$cur" "$tmp" # the new content goes into a copy, so owner and mode carry over

if cmp -s "$cur" "$old"; then
    cat "$new"
else
    # A rule is a non-comment line plus the lines it continues onto with a
    # trailing backslash and, when it says "chain", the rule chained to it.
    # Rules are compared with all whitespace removed, so indentation, line
    # wrapping and CRLF endings do not matter. Prints the upgraded file, or
    # nothing if no rule was replaced.
    awk -v default_path="$new" '
        FNR == 1 { f++ }    # f: 1 = OLD_DEFAULT, 2 = NEW_DEFAULT, 3 = CURRENT

        rule == "" && /^[ \t\r]*(#|$)/ {    # comment or blank line between rules
            if (f == 3) out = out $0 "\n"
            next
        }

        {
            rule = rule $0 "\n"
            line = $0
            continued = sub(/\\[ \t\r]*$/, "", line)
            stmt = stmt line
            if (continued) next
            gsub(/[ \t\r]/, "", stmt)
            key = key stmt
            chained = stmt ~ /[",]chain[",]/
            stmt = ""
            if (chained) next

            id = match(key, /[",]id:[0-9]+/) ? substr(key, RSTART + 4, RLENGTH - 4) : ""
            if (f == 1 && id != "") old_key[id] = key
            if (f == 2 && id != "") { new_key[id] = key; new_rule[id] = rule }
            if (f == 3 && (id in old_key) && old_key[id] != new_key[id]) {
                if (key == old_key[id]) { rule = new_rule[id]; replaced++ }
                else if (key != new_key[id]) edited = edited " " id
            }
            if (f == 3) out = out rule
            rule = key = ""
        }

        END {
            if (edited != "") {
                msg = "[Entrypoint] WARN: modsec/custom-rules.conf: rule(s)" edited
                msg = msg " edited locally and NOT upgraded. Replace them with the versions in "
                msg = msg default_path " (v2.60.1 security fix: the health-check and Socket.IO"
                msg = msg " exemptions decide on the normalized path; a WebSocket header no longer"
                msg = msg " switches the WAF off)"
                print msg > "/dev/stderr"
            }
            if (replaced) printf "%s", out rule
        }
    ' "$old" "$new" "$cur"
fi >"$tmp"

[ -s "$tmp" ] || exit 0
[ -e "$backup" ] || cp -p "$cur" "$backup"
mv -f "$tmp" "$cur"
echo "[Entrypoint] Upgraded NPG's rules in modsec/custom-rules.conf (other rules unchanged; previous file kept as ${backup##*/})"
