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
    # Cloudflare and OCI run inventoried managed-DNS pools too, so a delegation
    # into either is judgeable — and takeover-prone once the zone is deleted.
    assert is_cloud_nameserver("dana.ns.cloudflare.com")
    assert is_cloud_nameserver("ns1.p68.dns.oraclecloud.net")
    assert not is_cloud_nameserver("ns1.registrar.example")
    assert not is_cloud_nameserver("ns1.digitalocean.com")
    # Provider tokens inside unrelated hostnames are not provider DNS suffixes.
    assert not is_cloud_nameserver("ns-1.awsdns-01.org.attacker.example")
    assert not is_cloud_nameserver("notawsdns.example.com")
    assert not is_cloud_nameserver("fake.azure-dns.attacker.example")
    assert not is_cloud_nameserver("cloud.goog.attacker.example")
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
    # Azure ALIAS records carry an ARM resource id, not a hostname. These must
    # be attributed to Azure, not filed under third-party SaaS.
    arm = "/subscriptions/1111/resourcegroups/rg/providers/microsoft.network/publicipaddresses/pip"
    assert _classify_target(arm) == "Microsoft Azure"
    assert _classify_target(arm.upper()) == "Microsoft Azure"
    assert _classify_target("ns-1.awsdns-01.org") == "Amazon Web Services"
    # Provider-looking substrings outside a DNS label suffix stay External.
    assert _classify_target("evilcloudfront.net.attacker.example") == "External"
    assert _classify_target("fake.azure-dns.attacker.example") == "External"
    assert _classify_target("cloud.goog.attacker.example") == "External"
    assert _classify_target("notawsdns.example.com") == "External"
    # A path-looking value that isn't an ARM id stays External.
    assert _classify_target("/subscriptions/1111/something/else") == "External"


def test_identify_service():
    # Known SaaS takeover fingerprints.
    assert identify_service("foo.github.io.") == "GitHub Pages"
    assert identify_service("APP.HEROKUAPP.COM") == "Heroku"
    assert identify_service("shop.myshopify.com") == "Shopify"
    assert identify_service("site.netlify.app") == "Netlify"
    assert identify_service("docs.readme.io") == "Readme"
    assert identify_service("repo.bitbucket.io") == "Bitbucket"
    assert identify_service("blog.wordpress.com") == "WordPress.com"
    assert identify_service("x.trydiscourse.com") == "Discourse"
    # can-i-take-over-xyz lists these as not vulnerable (they verify ownership).
    assert identify_service("cdn.fastly.net") is None
    assert identify_service("help.zendesk.com") is None
    assert identify_service("status.statuspage.io") is None
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


def test_exclusions_ipv4_ipv6_and_domains():
    ex = findmytakeover._parse_exclusions(
        {"exclude": {"ipaddress": ["100.1.0.0/16", "2001:db8::/32"], "domains": ["example.com"]}}
    )
    # Networks are kept as networks, not expanded to 65k individual addresses.
    assert len(ex.networks) == 2
    assert ex.matches("100.1.2.3")
    assert ex.matches("2001:db8::5")          # IPv6 used to raise AddressValueError
    assert ex.matches("a.example.com")
    assert not ex.matches("9.9.9.9")
    assert not ex.matches("a.other.net")
    # Absent / empty config is not an error.
    assert not findmytakeover._parse_exclusions({})
    assert not findmytakeover._parse_exclusions({"exclude": None})


def test_find_dangling_accepts_legacy_exclusion_iterable():
    records = [["aws", "1", "a.example.com", "8.8.8.8"], ["aws", "1", "b.example.com", "1.1.1.1"]]
    infra = []
    # A plain set of substrings (the pre-_Exclusions calling convention) still works.
    assert _dangling_values(records, infra) == {"8.8.8.8", "1.1.1.1"}
    result = _find_dangling_records(
        pd.DataFrame(records, columns=RECORD_COLS),
        pd.DataFrame(infra, columns=INFRA_COLS),
        exclusions={"8.8.8.8"},
    )
    assert set(result["dnsvalue"]) == {"1.1.1.1"}


def test_json_report_shape():
    import json as _json
    import tempfile

    findings = [
        {"record": "a.example.com", "target": "gone.github.io", "dns_provider": "aws",
         "account": "111", "target_owner": "External", "saas_service": "GitHub Pages",
         "dns_status": "nxdomain", "confidence": "high"},
        {"record": "b.example.com", "target": "x.elb.amazonaws.com", "dns_provider": "aws",
         "account": "111", "target_owner": "Amazon Web Services", "saas_service": None,
         "dns_status": None, "confidence": "inventory-miss"},
    ]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "report.json")
        findmytakeover._write_json_report(path, findings, hidden_internal=3)
        with open(path) as fh:
            report = _json.load(fh)
    assert report["tool"] == "findmytakeover"
    assert report["summary"]["total"] == 2
    assert report["summary"]["high_confidence"] == 1
    assert report["summary"]["hidden_internal"] == 3
    assert report["summary"]["by_target_owner"]["External"] == 1
    assert len(report["findings"]) == 2


def test_alias_s3_and_ipv6_values_match_inventory():
    records = [
        # Route 53 alias: dualstack. prefix, trailing dot, mixed case.
        ["aws", "1", "www.example.com.", "dualstack.My-LB-1.us-east-1.elb.amazonaws.com."],
        ["aws", "1", "cdn.example.com.", "d111.cloudfront.net."],
        # S3 endpoints reduce to the bucket name, which may itself contain dots.
        ["aws", "1", "site.example.com.", "site.example.com.s3-website-us-east-1.amazonaws.com"],
        ["aws", "1", "assets.example.com.", "assets.s3.dualstack.us-gov-west-1.amazonaws.com"],
        ["aws", "1", "gone.example.com.", "deleted-bucket.s3.amazonaws.com"],
        # The same IPv6 address, spelled two ways.
        ["aws", "1", "v6.example.com.", "2001:DB8:0:0:0:0:0:1"],
    ]
    infra = [
        ["aws", "1", "elbv2", "my-lb-1.us-east-1.elb.amazonaws.com"],
        ["aws", "1", "cloudfront", "d111.cloudfront.net"],
        ["aws", "1", "s3", "site.example.com"],
        ["aws", "1", "s3", "assets"],
        ["aws", "1", "public-ip", "2001:db8::1"],
    ]
    assert _dangling_values(records, infra) == {"deleted-bucket.s3.amazonaws.com"}


def test_exclusions_match_dns_suffixes_not_substrings():
    ex = findmytakeover._parse_exclusions({"exclude": {"domains": ["example.com"]}})
    assert ex.matches("a.EXAMPLE.com.")
    assert ex.matches("example.com")
    assert not ex.matches("notexample.com")
    assert not ex.matches("example.com.attacker.example")


def test_secondary_targets():
    from collector import secondary_targets

    assert secondary_targets("MX", "10 mx.Example.com.") == ["mx.example.com"]
    assert secondary_targets("MX", "mx.example.com") == ["mx.example.com"]  # Cloudflare: no priority
    assert secondary_targets("MX", "0 .") == []  # null MX
    assert secondary_targets("SRV", "1 10 5060 sip.example.com.") == ["sip.example.com"]
    spf = '"v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -include:mail.zendesk.com" " ~include:%{i}.x.example redirect=spf.example.net"'
    assert secondary_targets("TXT", spf) == ["_spf.google.com", "mail.zendesk.com", "spf.example.net"]
    # A TXT value split into 255-byte chunks mid-token is rejoined first.
    assert secondary_targets("TXT", '"v=spf1 incl" "ude:a.example.com"') == ["a.example.com"]
    assert secondary_targets("TXT", '"google-site-verification=abc"') == []
    assert secondary_targets("TXT", "v=spf1 -all") == []


def test_secondary_records_reported_only_when_target_is_gone():
    records = [
        ["aws", "1", "example.com.", "aspmx.l.google.com", "MX"],
        ["aws", "1", "example.com.", "expired-mailhost.example", "MX"],
        ["aws", "1", "example.com.", "x.us-east-1.elb.amazonaws.com", "MX"],
    ]
    result = _find_dangling_records(
        pd.DataFrame(records, columns=RECORD_COLS + ["rtype"]),
        pd.DataFrame([], columns=INFRA_COLS),
        exclusions=set(),
    )
    # All three miss inventory; main() keeps the cloud one as an inventory-miss
    # and resolves the third-party ones, reporting only NXDOMAIN targets.
    assert set(result["rtype"]) == {"MX"}
    assert _classify_target("aspmx.l.google.com") == "External"
    assert _classify_target("x.us-east-1.elb.amazonaws.com") == "Amazon Web Services"


def test_us_government_names():
    assert is_cloud_nameserver("ns1-08.azuregov-dns.us.")
    for host in ("x.usgovcloudapi.net", "app.azurewebsites.us", "p.usgovtrafficmanager.net",
                 "r.azurecr.us", "s.search.azure.us", "f.azurefd.us"):
        assert _classify_target(host) == "Microsoft Azure", host
    assert _classify_target("x.execute-api.us-gov-west-1.amazonaws.com") == "Amazon Web Services"
    assert _classify_target("auth.auth.us-east-1.amazoncognito.com") == "Amazon Web Services"


def test_parse_providers_cloud_option():
    providers = _parse_providers(
        {"dns": {"azure": {"enabled": True, "credentials": "default", "cloud": "AzureUSGovernment"}}}, "dns"
    )
    assert providers["azure"]["options"] == {"cloud": "AzureUSGovernment"}
    try:
        _parse_providers({"dns": {"aws": {"enabled": True, "credentials": "default", "cloud": "x"}}}, "dns")
    except SystemExit:
        pass
    else:
        raise AssertionError("cloud: on a non-Azure provider must be rejected")


def test_empty_config_file_exits_cleanly():
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".config", delete=False) as fh:
        path = fh.name
    try:
        findmytakeover.read_config(path)
    except SystemExit as e:
        assert e.code == 1
    else:
        raise AssertionError("an empty config must exit, not crash")
    finally:
        os.unlink(path)


def test_collection_errors_reported():
    import json as _json
    import tempfile

    errors = [
        {"provider": "Amazon Web Services", "scope": "1/us-east-1", "what": "rds", "error": "AccessDenied"},
        {"provider": "Amazon Web Services", "scope": "1/eu-west-1", "what": "rds", "error": "AccessDenied"},
    ]
    assert findmytakeover._summarise_errors(errors) == [
        (("Amazon Web Services", "rds", "AccessDenied"), 2)
    ]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "report.json")
        findmytakeover._write_json_report(path, [], 0, errors)
        with open(path) as fh:
            report = _json.load(fh)
    assert report["summary"]["complete"] is False
    assert len(report["collection_errors"]) == 2


def test_http_fingerprint_status():
    from collector.fingerprints import http_fingerprint

    class _Raw:
        def __init__(self, body):
            self.body = body

        def read(self, n, decode_content=True):
            return self.body[:n]

    class _Response:
        encoding = "utf-8"

        def __init__(self, body):
            self.raw = _Raw(body)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Session:
        def __init__(self, pages):
            self.pages = pages

        def get(self, url, **kwargs):
            page = self.pages.get(url)
            if page is None:
                raise ConnectionError(url)
            return _Response(page)

    pattern = http_fingerprint("GitHub Pages")
    gone = _Session({"https://docs.example.com": b"<h1>There isn't a GitHub Pages site here.</h1>"})
    live = _Session({"https://docs.example.com": b"<h1>Docs</h1>"})
    http_only = _Session({"http://docs.example.com": b"There isn't a GitHub Pages site here."})
    status = findmytakeover._http_fingerprint_status
    assert status(gone, "docs.example.com", pattern) == "matched"
    assert status(live, "docs.example.com", pattern) == "no-match"
    assert status(http_only, "docs.example.com", pattern) == "matched"
    assert status(_Session({}), "docs.example.com", pattern) == "unknown"
    assert http_fingerprint("Unknown service") is None


def test_aws_region_collectors_are_isolated():
    from botocore.exceptions import ClientError, EndpointConnectionError

    import collector
    from collector import aws

    def denied(make):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Describe")
        yield

    def not_offered(make):
        raise EndpointConnectionError(endpoint_url="https://x")
        yield

    def works(make):
        yield "lb.example.elb.amazonaws.com"
        yield None

    original = aws._REGIONAL_COLLECTORS
    collector.COLLECTION_ERRORS.clear()
    aws._REGIONAL_COLLECTORS = (("a", denied), ("b", not_offered), ("c", works))
    try:
        rows = aws._collect_region_infra("111122223333", "default", "us-east-1")
    finally:
        aws._REGIONAL_COLLECTORS = original
    errors = list(collector.COLLECTION_ERRORS)
    collector.COLLECTION_ERRORS.clear()
    assert rows == [["111122223333", "c", "lb.example.elb.amazonaws.com"]]
    # A denied API is a gap worth reporting; a service absent from the region isn't.
    assert [(e["what"], e["error"]) for e in errors] == [("a", "An error occurred (AccessDenied) when calling the Describe operation: no")]


def test_aws_govcloud_partition():
    from collector import aws

    assert aws._partition("us-gov-west-1") == "aws-us-gov"
    assert aws._partition("us-east-1") == "aws"
    assert not aws._offered_in("cloudfront", "us-gov-west-1")
    assert aws._offered_in("cloudfront", "us-east-1")


def test_s3_hostname_regex_is_linear():
    import time

    from findmytakeover import _S3_HOSTNAME, _match_key

    assert _match_key("b.s3-website.us-east-1.amazonaws.com") == "b"
    assert _match_key("my-bucket.s3.amazonaws.com") == "my-bucket"
    # CodeQL ReDoS reproducer: overlapping "-" handling made this exponential.
    start = time.monotonic()
    assert _S3_HOSTNAME.match("a.s3-" + "--" * 5000 + "!") is None
    assert time.monotonic() - start < 1.0


def _finding(record, target, record_type=None, confidence="inventory-miss"):
    return {"record": record, "record_type": record_type, "target": target,
            "target_owner": "External", "confidence": confidence}


def test_compare_with_baseline():
    baseline = [
        _finding("a.example.com", "gone.github.io"),
        _finding("fixed.example.com", "old.herokuapp.com"),
        _finding("example.com", "mx.dead.example", "MX"),
    ]
    findings = [
        # Same finding; confidence changing between runs doesn't make it new.
        _finding("A.example.com.", "gone.github.io.", confidence="high"),
        _finding("b.example.com", "x.netlify.app"),
        # Same record and target but a different type is a different finding.
        _finding("example.com", "mx.dead.example", "TXT"),
    ]
    diff = findmytakeover._compare_with_baseline(findings, baseline)
    assert [f["new"] for f in findings] == [False, True, True]
    assert [f["record"] for f in diff["new"]] == ["b.example.com", "example.com"]
    assert [f["record"] for f in diff["resolved"]] == ["fixed.example.com", "example.com"]
    assert diff["resolved"][1]["record_type"] == "MX"


def test_load_baseline():
    import json as _json
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        # First scheduled run: no previous report yet.
        assert findmytakeover._load_baseline(os.path.join(d, "missing.json")) == []

        good = os.path.join(d, "good.json")
        with open(good, "w") as fh:
            _json.dump({"findings": [_finding("a.example.com", "t.example")]}, fh)
        assert len(findmytakeover._load_baseline(good)) == 1

        # A corrupt baseline must not silently re-alert on everything.
        for content in ("{not json", '{"summary": {}}'):
            bad = os.path.join(d, "bad.json")
            with open(bad, "w") as fh:
                fh.write(content)
            try:
                findmytakeover._load_baseline(bad)
            except SystemExit as e:
                assert e.code == 1
            else:
                raise AssertionError(f"bad baseline accepted: {content}")


def test_exit_codes():
    from types import SimpleNamespace

    def code(fail_findings, fail_incomplete, findings, incomplete):
        args = SimpleNamespace(fail_on_findings=fail_findings, fail_on_incomplete=fail_incomplete)
        return findmytakeover._exit_code(args, findings, incomplete)

    assert code(False, False, 5, True) == 0   # both opt-in
    assert code(True, False, 5, True) == 1
    assert code(True, False, 0, True) == 0
    assert code(False, True, 0, True) == 2
    assert code(True, True, 3, True) == 1    # findings outrank an incomplete scan
    assert code(True, True, 0, False) == 0


def test_json_report_with_baseline_diff():
    import json as _json
    import tempfile

    new = _finding("b.example.com", "x.netlify.app")
    new["new"] = True
    diff = {"new": [new], "resolved": [_finding("fixed.example.com", "old.herokuapp.com")]}
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "report.json")
        findmytakeover._write_json_report(path, [new], 0, (), diff)
        with open(path) as fh:
            report = _json.load(fh)
    assert report["summary"]["new"] == 1
    assert report["summary"]["resolved"] == 1
    assert report["resolved"][0]["record"] == "fixed.example.com"
    assert report["findings"][0]["new"] is True
