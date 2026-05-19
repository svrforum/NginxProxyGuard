# scripts/extract-schema.jq
# Input: array of ModSecurity audit JSON entries.
# Output: schema of the first entry — every leaf replaced by its JSON type
# name. Object keys are sorted so the output is stable across runs and diffs
# cleanly against the committed lockfile.
#
# Arrays: we recurse into element 0 only. ModSec audit arrays in practice
# (messages, tags, components) are homogeneous, so the first element's shape
# is representative. Heterogeneous arrays would lose type info for tail
# elements — call out as a known limitation if it ever bites.

def schema_of:
  if type == "object" then
    to_entries
    | map({key, value: (.value | schema_of)})
    | sort_by(.key)
    | from_entries
  elif type == "array" then
    if length > 0 then [.[0] | schema_of] else ["empty"] end
  else
    type
  end;

if length == 0 then "no audit entries"
else .[0] | schema_of
end
