#!/usr/bin/env python3
"""Self-check for dangling NS-delegation and Azure ALIAS detection.

Runs the real diff engine (findmytakeover._find_dangling_records) over synthetic
inventories — no cloud calls. Run: python3 tests/test_dangling.py
"""

import os
import sys

# Make the repo root importable regardless of where the test is run from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from collector import is_cloud_nameserver, zone_key
from findmytakeover import (
    _find_dangling_records,
    _parse_providers,
    _is_internal_record,
    _classify_target,
)

RECORD_COLS = ["csp", "account", "dnskey", "dnsvalue"]
INFRA_COLS = ["csp", "account", "service", "value"]


def _dangling_values(records, infra):
    result = _find_dangling_records(
        pd.DataFrame(records, columns=RECORD_COLS),
        pd.DataFrame(infra, columns=INFRA_COLS),
        exclusions=set(),
    )
    return {result.loc[i, "dnsvalue"] for i in result.index if result.loc[i, "value"] == ""}


def test_helpers():
    assert is_cloud_nameserver("ns-1.awsdns-01.org")
    assert is_cloud_nameserver("ns1-01.AZURE-DNS.com")
    assert is_cloud_nameserver("ns-cloud-a1.googledomains.com")
    assert not is_cloud_nameserver("dana.ns.cloudflare.com")
    assert not is_cloud_nameserver("ns1.registrar.example")
    assert zone_key("Sub.Example.COM.") == "sub.example.com"


def test_dangling_ns_delegation():
    records = [
        # delegation whose child zone is gone → dangling
        ["aws", "111", "gone.example.com.", "gone.example.com"],
        # delegation whose child zone still exists (in some scanned account) → live
        ["aws", "111", "live.example.com.", "live.example.com"],
    ]
    infra = [["aws", "222", "hostedzone", "live.example.com"]]
    assert _dangling_values(records, infra) == {"gone.example.com"}


def test_azure_alias():
    gone_id = "/subscriptions/s/rg/providers/microsoft.network/publicipaddresses/gone"
    live_id = "/subscriptions/s/rg/providers/microsoft.network/publicipaddresses/live"
    records = [
        ["azure", "s", "gone.example.com", zone_key(gone_id)],
        ["azure", "s", "live.example.com", zone_key(live_id)],
    ]
    infra = [["azure", "s", "publicip", zone_key(live_id)]]
    assert _dangling_values(records, infra) == {zone_key(gone_id)}


def test_empty_provider_block():
    # An empty provider block parses as None — must be skipped, not crash.
    assert _parse_providers({"dns": {"aws": None}}, "dns") == {}
    # A disabled provider is also skipped.
    assert _parse_providers({"dns": {"aws": {"enabled": False}}}, "dns") == {}


def test_internal_record_filter():
    # Internal / private → hidden
    assert _is_internal_record("kube-dns.kube-system.svc.cluster.local", "10.8.0.10")
    assert _is_internal_record("orchestrator.myapp.svc.cluster.local", "34.118.224.1")  # public-range GKE svc IP
    assert _is_internal_record("host.dev.cloud.example.com.", "10.0.204.170")
    # Real public takeover targets → shown
    assert not _is_internal_record("app.example.com.", "d1odiojnqoo3w8.cloudfront.net.")
    assert not _is_internal_record("auth.example.com.", "198.202.211.1")


def test_classify_target():
    assert _classify_target("my-lb-1234567890.us-east-1.elb.amazonaws.com.") == "Amazon Web Services"
    assert _classify_target("d1odiojnqoo3w8.cloudfront.net.") == "Amazon Web Services"
    assert _classify_target("55c02fa8.4.us-west1.authorize.certificatemanager.goog.") == "Google Cloud Platform"
    assert _classify_target("app.trafficmanager.net") == "Microsoft Azure"
    assert _classify_target("statuspage.betteruptime.com") == "External"
    assert _classify_target("198.202.211.1") == "External"


if __name__ == "__main__":
    test_helpers()
    test_dangling_ns_delegation()
    test_azure_alias()
    test_empty_provider_block()
    test_internal_record_filter()
    test_classify_target()
    print("ok")
