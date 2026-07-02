#!/usr/bin/env bash
# Cross-reference A-record IPs against cloud inventory you actually own, so a
# "no HTTP response" candidate is only called dangling when it's ALSO not owned.
# Usage: bash audit_a_inventory.sh <outdir> [aws_profiles] [gcp] [azure]
#   <outdir>      dir produced by find_dangling.sh (needs a_records.tsv)
#   aws_profiles  space-separated, quoted, e.g. "dns prof-prod staging" (default: none)
#   gcp           "yes" to sweep all gcloud projects (needs gcloud auth)
#   azure         "yes" to sweep all az subscriptions (needs az login)
set -uo pipefail
OUT="${1:?outdir from find_dangling.sh}"
AWS_PROFILES="${2:-}"
DO_GCP="${3:-no}"
DO_AZURE="${4:-no}"
REGIONS="${REGIONS:-us-east-1 us-east-2 us-west-1 us-west-2 sa-east-1 eu-west-1 ap-south-1}"
[ -f "$OUT/a_records.tsv" ] || { echo "missing $OUT/a_records.tsv — run find_dangling.sh first"; exit 1; }

OWNED="$OUT/owned_ips.txt"; : > "$OWNED"

for p in $AWS_PROFILES; do
  for r in $REGIONS; do
    aws ec2 describe-network-interfaces --profile "$p" --region "$r" \
      --query 'NetworkInterfaces[].Association.PublicIp' --output text 2>/dev/null | tr '\t' '\n' >> "$OWNED"
    aws ec2 describe-addresses --profile "$p" --region "$r" \
      --query 'Addresses[].PublicIp' --output text 2>/dev/null | tr '\t' '\n' >> "$OWNED"
  done
  echo "  swept aws:$p" >&2
done

if [ "$DO_GCP" = yes ]; then
  for proj in $(gcloud projects list --format="value(projectId)" 2>/dev/null); do
    gcloud compute addresses list --project "$proj" --format="value(address)" 2>/dev/null >> "$OWNED"
    gcloud compute instances list --project "$proj" \
      --format="value(networkInterfaces[].accessConfigs[].natIP)" 2>/dev/null | tr ';,' '\n' >> "$OWNED"
    echo "  swept gcp:$proj" >&2
  done
fi

if [ "$DO_AZURE" = yes ]; then
  for sub in $(az account list --query "[].id" -o tsv 2>/dev/null); do
    az network public-ip list --subscription "$sub" --query "[].ipAddress" -o tsv 2>/dev/null >> "$OWNED"
    echo "  swept azure:$sub" >&2
  done
fi

grep -E '^[0-9]+\.' "$OWNED" | sort -u > "$OUT/owned_sorted.txt"
echo "Owned public IPs found: $(wc -l < "$OUT/owned_sorted.txt")"

# Verdict: an A-record IP is a dangling candidate only if NOT owned. Combine with
# the no-HTTP signal from find_dangling (dangling_a.tsv) for high confidence.
echo
echo "=== A-record IP ownership (NOT-FOUND + no-HTTP = dangling) ==="
awk '{print $2}' "$OUT/a_records.tsv" | sort -u | while read -r ip; do
  grep -qx "$ip" "$OUT/owned_sorted.txt" && v=OWNED || v=NOT-FOUND
  nohttp=""; grep -q "^$ip	" "$OUT/dangling_a.tsv" 2>/dev/null && nohttp="no-HTTP"
  hosts=$(awk -v ip="$ip" '$2==ip{printf "%s ",$1}' "$OUT/a_records.tsv")
  printf '%-16s %-10s %-8s %s\n' "$ip" "$v" "$nohttp" "$hosts"
done | sort -k2,2 -k3,3
