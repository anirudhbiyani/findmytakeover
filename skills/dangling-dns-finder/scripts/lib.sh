#!/usr/bin/env bash
# Shared helpers for the dangling-dns-finder scripts.

# classify_target <target-hostname> -> echoes one of:
#   cert-validation | dkim | endpoint
# Validation/DKIM targets are NOT subdomain-takeover risks even when NXDOMAIN
# (single-use tokens / live SaaS provider zones). Only "endpoint" matters.
classify_target() {
  case "$1" in
    *acm-validations.aws|*acm-validations.aws.) echo cert-validation ;;
    *certificatemanager.goog|*certificatemanager.goog.) echo cert-validation ;;
    *dkim*|*domainkey*|*custdkim*|*hubspotemail.net*|*deliver.highspot.com*|*freshemail.io*) echo dkim ;;
    *) echo endpoint ;;
  esac
}

# dig_status <name> [resolver] -> echoes NXDOMAIN/NOERROR/SERVFAIL/... or NORESP
dig_status() {
  local r=""
  [ -n "${2:-}" ] && r="@$2"
  dig $r +noall +comments "$1" A 2>/dev/null \
    | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}' | grep . || echo NORESP
}
