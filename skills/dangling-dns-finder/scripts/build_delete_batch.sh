#!/usr/bin/env bash
# Build a Route53 change-batch that DELETEs the named records, sourcing exact
# TTL/values from the live zone dump (DELETE requires an exact match).
# Usage: bash build_delete_batch.sh <records.json> <names.txt> [out.json]
#   names.txt = one FQDN per line, WITH trailing dot, matching record .Name
# NOTE: matches by name, so it deletes ALL record types at a matched name.
#       If a dangling name also carries a record you want to keep, edit by hand.
set -euo pipefail
REC="${1:?records.json}"; NAMES="${2:?names.txt}"; OUT="${3:-delete-batch.json}"

jq --rawfile names "$NAMES" '
  ($names | split("\n") | map(select(length>0))) as $del
  | {Changes: [ .ResourceRecordSets[]
      | select(.Name as $n | $del | index($n))
      | {Action:"DELETE", ResourceRecordSet: .} ]}' "$REC" > "$OUT"

got=$(jq '.Changes|length' "$OUT"); want=$(grep -c . "$NAMES")
echo "Changes in batch: $got   (names requested: $want)"
[ "$got" = "$want" ] || echo "WARNING: count mismatch — names didn't all match the dump. Don't apply until resolved."
echo
echo "Apply (review first; this is hard to reverse):"
echo "  aws route53 change-resource-record-sets --hosted-zone-id <ZID> --change-batch file://$OUT --profile <PROFILE>"
