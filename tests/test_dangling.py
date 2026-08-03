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

import findmytakeover
from collector import is_cloud_nameserver, zone_key
from collector.fingerprints import identify_service
from findmytakeover import (
    _DNSPYTHON_AVAILABLE,
    _find_dangling_records,
    _parse_providers,
    _is_internal_record,
    _classify_target,
    _resolve_hostname_status,
    _verify_dns_targets,
)

if _DNSPYTHON_AVAILABLE:
    import dns.exception
    import dns.resolver


class _StubResolver:
    """Fake dnspython resolver for tests -- no real DNS queries are made.

    `plan` maps a hostname to one of "ok" / "nxdomain" / "noanswer" / "timeout".
    """

    def __init__(self, plan):
        self.plan = plan

    def resolve(self, name, rdtype):
        outcome = self.plan[name]
        if outcome == "nxdomain":
            raise dns.resolver.NXDOMAIN()
        if outcome == "noanswer":
            raise dns.resolver.NoAnswer()
        if outcome == "timeout":
            raise dns.exception.Timeout()
        return ["203.0.113.10"]

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


def test_identify_service():
    # Known SaaS takeover fingerprints.
    assert identify_service("foo.github.io.") == "GitHub Pages"
    assert identify_service("APP.HEROKUAPP.COM") == "Heroku"
    assert identify_service("shop.myshopify.com") == "Shopify"
    assert identify_service("site.netlify.app") == "Netlify"
    assert identify_service("cdn.fastly.net") == "Fastly"
    assert identify_service("help.zendesk.com") == "Zendesk"
    assert identify_service("docs.readme.io") == "Readme"
    assert identify_service("status.statuspage.io") == "Statuspage"
    assert identify_service("repo.bitbucket.io") == "Bitbucket"
    # Bare hostname equal to the fingerprinted suffix also matches.
    assert identify_service("herokudns.com") == "Heroku"
    # Not a SaaS fingerprint: unknown third party, and first-party cloud
    # targets (already classified elsewhere, not fingerprinted here).
    assert identify_service("random.example.com") is None
    assert identify_service("d1odiojnqoo3w8.cloudfront.net.") is None
    # Suffix must be a real hostname boundary, not just a substring.
    assert identify_service("evil-github.io.attacker.example") is None


def test_resolve_hostname_status_classification():
    if not _DNSPYTHON_AVAILABLE:
        print("dnspython not installed -- skipping DNS classification test")
        return

    resolver = _StubResolver({
        "gone.github.io": "nxdomain",
        "live.herokuapp.com": "ok",
        "flaky.netlify.app": "timeout",
        "noanswer.myshopify.com": "noanswer",
    })
    # NXDOMAIN -> high-confidence dangling.
    assert _resolve_hostname_status(resolver, "gone.github.io") == "nxdomain"
    # NOERROR (with or without an A record) -> still occupied.
    assert _resolve_hostname_status(resolver, "live.herokuapp.com") == "resolves"
    assert _resolve_hostname_status(resolver, "noanswer.myshopify.com") == "resolves"
    # Timeout/resolver error -> inconclusive, never a finding.
    assert _resolve_hostname_status(resolver, "flaky.netlify.app") == "unknown"


def test_verify_dns_targets_dedupes_and_classifies():
    if not _DNSPYTHON_AVAILABLE:
        print("dnspython not installed -- skipping DNS verify test")
        return

    calls = []
    stub = _StubResolver({
        "gone.github.io": "nxdomain",
        "live.herokuapp.com": "ok",
    })
    real_resolve = stub.resolve

    def counting_resolve(name, rdtype):
        calls.append(name)
        return real_resolve(name, rdtype)

    stub.resolve = counting_resolve

    original_make_resolver = findmytakeover._make_resolver
    findmytakeover._make_resolver = lambda: stub
    try:
        statuses = _verify_dns_targets(
            ["gone.github.io", "gone.github.io.", "GONE.GITHUB.IO", "live.herokuapp.com"]
        )
    finally:
        findmytakeover._make_resolver = original_make_resolver

    assert statuses == {"gone.github.io": "nxdomain", "live.herokuapp.com": "resolves"}
    # Each unique (normalized) hostname is resolved exactly once, even though
    # it was passed in three different casings/forms above.
    assert sorted(calls) == ["gone.github.io", "live.herokuapp.com"]

    # No hostnames / dnspython unavailable -> no-op, never raises.
    assert _verify_dns_targets([]) == {}


if __name__ == "__main__":
    test_helpers()
    test_dangling_ns_delegation()
    test_azure_alias()
    test_empty_provider_block()
    test_internal_record_filter()
    test_classify_target()
    test_identify_service()
    test_resolve_hostname_status_classification()
    test_verify_dns_targets_dedupes_and_classifies()
    print("ok")
