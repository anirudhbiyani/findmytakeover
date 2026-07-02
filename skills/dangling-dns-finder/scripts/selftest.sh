#!/usr/bin/env bash
# Self-check for the target classifier — the one bit of non-trivial logic that,
# if it breaks, silently mislabels validation records as takeover risks.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/lib.sh"

check() { # check <target> <expected>
  got=$(classify_target "$1")
  [ "$got" = "$2" ] || { echo "FAIL: $1 -> $got (expected $2)"; exit 1; }
}

check "_x.vybhcgkthd.acm-validations.aws"                 cert-validation
check "abc.1.us-west1.authorize.certificatemanager.goog" cert-validation
check "prophecy-io.hs18a.dkim.hubspotemail.net"          dkim
check "prophecy.io.48fps4.custdkim.salesforce.com"       dkim
check "wl414215s1.domainkey.freshemail.io"               dkim
check "hsp.prophecy.deliver.highspot.com"                dkim
check "a86a5d73.us-east-1.elb.amazonaws.com"             endpoint
check "k8s-prophecy-prophecy-x.elb.us-west-1.amazonaws.com" endpoint
check "some-vm.example.com"                              endpoint

echo "OK: classifier self-check passed (9 cases)"
