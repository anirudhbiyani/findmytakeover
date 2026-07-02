#!/usr/bin/env bash
# Find dangling / subdomain-takeover-prone records in a Route53 hosted zone.
# Usage: bash find_dangling.sh <zone_name> <aws_profile> [outdir]
#   e.g. bash find_dangling.sh cloud.prophecy.io dns ./out
# If the zone isn't in Route53, drop your own {"ResourceRecordSets":[...]} at
# <outdir>/records.json and set ZID=skip:  ZID=skip bash find_dangling.sh <zone> <profile> <outdir>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/lib.sh"

ZONE="${1:?zone name, e.g. example.com}"
PROFILE="${2:?aws profile}"
OUT="${3:-./dangling-$ZONE}"
mkdir -p "$OUT"

# 1. locate zone + dump records (unless caller supplied records.json with ZID=skip)
if [ "${ZID:-}" != "skip" ]; then
  ZID=$(aws route53 list-hosted-zones --profile "$PROFILE" \
        --query "HostedZones[?Name=='${ZONE}.'].Id" --output text 2>/dev/null \
        | tr '\t' '\n' | head -1 | sed 's#/hostedzone/##')
  [ -z "${ZID:-}" ] && { echo "Zone '$ZONE' not found in profile '$PROFILE'."; exit 1; }
  aws route53 list-resource-record-sets --hosted-zone-id "$ZID" --profile "$PROFILE" \
    --output json > "$OUT/records.json" || { echo "Failed to dump zone."; exit 1; }
fi
echo "Zone: $ZONE (${ZID:-supplied})  records: $(jq '.ResourceRecordSets|length' "$OUT/records.json")"

# 2. CNAME + ALIAS targets -> NXDOMAIN (verified x3), categorized
jq -r '.ResourceRecordSets[]
  | select(.Type=="CNAME" or (.Type=="A" and .AliasTarget!=null))
  | if .Type=="CNAME" then "\(.Name)\tCNAME\t\(.ResourceRecords[0].Value)"
    else "\(.Name)\tALIAS\t\(.AliasTarget.DNSName)" end' "$OUT/records.json" \
  | sed 's/\.$//' > "$OUT/targets.tsv"

: > "$OUT/dangling_cname.tsv"
while IFS=$'\t' read -r name type target; do
  [ -z "$target" ] && continue
  st=$(dig_status "$target")
  [ "$st" != NXDOMAIN ] && continue
  # re-verify on public resolvers to avoid single-resolver flukes
  [ "$(dig_status "$target" 8.8.8.8)" = NXDOMAIN ] || continue
  [ "$(dig_status "$target" 1.1.1.1)" = NXDOMAIN ] || continue
  printf '%s\t%s\t%s\n' "$target" "$(classify_target "$target")" "$name" >> "$OUT/dangling_cname.tsv"
done < "$OUT/targets.tsv"

# 3. A records -> HTTP liveness probe (portable, no cloud creds needed)
jq -r '.ResourceRecordSets[]|select(.Type=="A" and .ResourceRecords!=null)
       | .Name as $n | .ResourceRecords[] | "\($n)\t\(.Value)"' "$OUT/records.json" \
  | sed 's/\.\t/\t/' > "$OUT/a_records.tsv"

: > "$OUT/dangling_a.tsv"
cut -f1 "$OUT/a_records.tsv" | sort -u | while read -r host; do
  case "$host" in *'\'*) continue ;; esac   # escaped names break curl; verify by hand
  code=$(curl -sS -k -m 8 -o /dev/null -w '%{http_code}' "https://$host/" 2>/dev/null); rc=$?
  { [ "$rc" != 0 ] || [ "$code" = 000 ]; } && code=DEAD
  [ "$code" != DEAD ] && continue
  ip=$(awk -v n="$host" '$1==n{print $2}' "$OUT/a_records.tsv" | head -1)
  printf '%s\t%s\tno-HTTP\n' "$ip" "$host" >> "$OUT/dangling_a.tsv"
done

# 4. report + name lists for deletion
echo
echo "=== DANGLING CNAME/ALIAS  (target | category | name) — endpoint = takeover risk ==="
sort -t$'\t' -k2 "$OUT/dangling_cname.tsv" 2>/dev/null | column -s$'\t' -t || true
echo
echo "=== A RECORDS WITH NO HTTP RESPONSE (candidates — confirm with audit_a_inventory.sh) ==="
column -s$'\t' -t "$OUT/dangling_a.tsv" 2>/dev/null || true

{ awk -F'\t' '$2=="endpoint"{print $3}' "$OUT/dangling_cname.tsv"
  awk -F'\t' '{print $2}' "$OUT/dangling_a.tsv"; } | sed 's/\.*$/./' | sort -u > "$OUT/dangling_names.txt"
awk -F'\t' '$2!="endpoint"{print $3}' "$OUT/dangling_cname.tsv" | sed 's/\.*$/./' | sort -u > "$OUT/validation_names.txt"

echo
echo "Wrote:"
echo "  $OUT/dangling_names.txt    -> $(grep -c . "$OUT/dangling_names.txt" 2>/dev/null || echo 0) takeover-risk names"
echo "  $OUT/validation_names.txt  -> $(grep -c . "$OUT/validation_names.txt" 2>/dev/null || echo 0) stale validation (optional cleanup)"
echo "Next: bash audit_a_inventory.sh $OUT \"$PROFILE\"   then   build_delete_batch.sh $OUT/records.json <names> $OUT/delete-batch.json"
