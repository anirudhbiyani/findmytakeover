#!/usr/bin/env python3
"""Contract tests pinning the Cloudflare SDK shapes collector/cloudflare.py depends on.

The Workers/R2/Spectrum/Tunnel additions to collector/cloudflare.py were written
without live API access, so a dependabot bump to the `cloudflare` package that
silently renames or removes an accessor or response field should fail CI here
instead of quietly breaking takeover detection in production.

No network calls and no real Cloudflare credentials are used anywhere in this
file. `cloudflare.Cloudflare(api_token=...)` only builds an HTTP client and does
not make any request, so it is safe to construct and walk attribute-by-attribute.
Response models are pydantic v2 (`BaseModel`) - `model_fields` is a class-level
dict, so no instantiation is needed to inspect fields.

Run: python3 -m pytest tests/test_contract_cloudflare.py -v
"""

import pytest


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _assert_accessor(obj, path):
    """Assert every dotted step in `path` exists on `obj` (via hasattr),
    walking the chain attribute by attribute (no calls are made).

    Failure names the exact step that disappeared so a dependabot-bump
    breakage points straight at collector/cloudflare.py's usage.
    """
    cur = obj
    trail = []
    for part in path.split("."):
        trail.append(part)
        assert hasattr(cur, part), (
            f"{type(obj).__module__}.{type(obj).__qualname__} no longer has "
            f"accessor '{'.'.join(trail)}' (from path '{path}') - "
            f"collector/cloudflare.py calls this; update it to match the new "
            f"SDK shape (or the shape genuinely broke)."
        )
        cur = getattr(cur, part)
    return cur


def _assert_model_field(model_cls, field):
    """Assert `field` is a declared pydantic field on `model_cls`.

    Failure names the model class and the missing field so a dependabot-bump
    breakage points straight at collector/cloudflare.py's usage.
    """
    assert field in model_cls.model_fields, (
        f"{model_cls.__module__}.{model_cls.__qualname__} no longer has "
        f"field '{field}' - collector/cloudflare.py reads this; update it "
        f"to match the new SDK shape (or the shape genuinely broke)."
    )


# --------------------------------------------------------------------------
# Negative controls - prove the assertions above can't pass vacuously.
# --------------------------------------------------------------------------


def test_negative_control_bogus_accessor_is_absent():
    pytest.importorskip("cloudflare")
    import cloudflare

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    # A real accessor is present ...
    assert hasattr(client.workers, "subdomains")
    # ... but a made-up one is not, and _assert_accessor must catch that.
    assert not hasattr(client.workers, "totally_bogus_xyz")
    with pytest.raises(AssertionError, match="no longer has"):
        _assert_accessor(client, "workers.totally_bogus_xyz")


def test_negative_control_bogus_model_field_is_absent():
    pytest.importorskip("cloudflare")
    from cloudflare.types.zones import Zone

    # A real field is present ...
    assert "name" in Zone.model_fields
    # ... but a made-up one is not, and _assert_model_field must catch that.
    assert "totally_bogus_field_xyz" not in Zone.model_fields
    with pytest.raises(AssertionError, match="no longer has"):
        _assert_model_field(Zone, "totally_bogus_field_xyz")


# --------------------------------------------------------------------------
# Client construction, APIError, accounts/zones - shared plumbing
# --------------------------------------------------------------------------


def test_client_and_top_level_accessors_contract():
    pytest.importorskip("cloudflare")
    import cloudflare

    # Constructing the client does no network I/O.
    client = cloudflare.Cloudflare(api_token="dummy-not-used")

    assert hasattr(cloudflare, "APIError")  # imported and caught around every call

    _assert_accessor(client, "accounts.list")  # _resolve_accounts()
    _assert_accessor(client, "zones.list")  # dns(), infra()

    from cloudflare.types.accounts import Account
    from cloudflare.types.zones import Zone

    _assert_model_field(Account, "id")  # account.id
    _assert_model_field(Zone, "id")  # zone.id
    _assert_model_field(Zone, "name")  # zone.name


# --------------------------------------------------------------------------
# DNS records - A/AAAA/CNAME/NS members of the RecordResponse union
# --------------------------------------------------------------------------


def test_dns_records_contract():
    pytest.importorskip("cloudflare")
    import cloudflare
    from cloudflare.types.dns import record_response as rr

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    _assert_accessor(client, "dns.records.list")

    # record.name / record.content / record.type are read unconditionally
    # for every record returned, before branching on `type`; the collector
    # only actually acts on A/AAAA/CNAME (dns()) and NS (child-delegation
    # detection), so those are the members pinned here.
    for name in ("ARecord", "AAAARecord", "CNAMERecord", "NSRecord"):
        cls = getattr(rr, name)
        _assert_model_field(cls, "name")
        _assert_model_field(cls, "content")
        _assert_model_field(cls, "type")


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


def test_pages_contract():
    pytest.importorskip("cloudflare")
    import cloudflare
    from cloudflare.types.pages import Project

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    _assert_accessor(client, "pages.projects.list")

    _assert_model_field(Project, "subdomain")
    _assert_model_field(Project, "domains")


# --------------------------------------------------------------------------
# Workers - subdomain, scripts, custom domains
# --------------------------------------------------------------------------


def test_workers_contract():
    pytest.importorskip("cloudflare")
    import cloudflare
    from cloudflare.types.workers import (
        SubdomainGetResponse,
        ScriptListResponse,
        DomainListResponse,
    )

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    _assert_accessor(client, "workers.subdomains.get")
    _assert_accessor(client, "workers.scripts.list")
    _assert_accessor(client, "workers.domains.list")

    _assert_model_field(SubdomainGetResponse, "subdomain")
    _assert_model_field(ScriptListResponse, "id")
    _assert_model_field(DomainListResponse, "hostname")


# --------------------------------------------------------------------------
# R2 - buckets, managed (r2.dev) domains, custom domains
# --------------------------------------------------------------------------


def test_r2_contract():
    pytest.importorskip("cloudflare")
    import cloudflare
    from cloudflare.types.r2 import Bucket, BucketListResponse
    from cloudflare.types.r2.buckets.domains import ManagedListResponse, CustomListResponse
    from cloudflare.types.r2.buckets.domains.custom_list_response import Domain

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    _assert_accessor(client, "r2.buckets.list")
    _assert_accessor(client, "r2.buckets.domains.managed.list")
    _assert_accessor(client, "r2.buckets.domains.custom.list")

    _assert_model_field(BucketListResponse, "buckets")
    _assert_model_field(Bucket, "name")
    _assert_model_field(ManagedListResponse, "domain")
    _assert_model_field(CustomListResponse, "domains")
    _assert_model_field(Domain, "domain")


# --------------------------------------------------------------------------
# Zero Trust Tunnels
# --------------------------------------------------------------------------


def test_tunnels_contract():
    pytest.importorskip("cloudflare")
    import cloudflare
    from cloudflare.types.shared import CloudflareTunnel

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    _assert_accessor(client, "zero_trust.tunnels.cloudflared.list")

    _assert_model_field(CloudflareTunnel, "id")


# --------------------------------------------------------------------------
# Custom Hostnames (Cloudflare for SaaS), Load Balancers, Spectrum
# --------------------------------------------------------------------------


def test_saas_loadbalancer_spectrum_contract():
    pytest.importorskip("cloudflare")
    import cloudflare
    from cloudflare.types.custom_hostnames import CustomHostnameListResponse
    from cloudflare.types.load_balancers import LoadBalancer
    from cloudflare.types.spectrum import DNS
    from cloudflare.types.spectrum.app_list_response import (
        SpectrumConfigAppConfig,
        SpectrumConfigPaygoAppConfig,
    )

    client = cloudflare.Cloudflare(api_token="dummy-not-used")
    _assert_accessor(client, "custom_hostnames.list")
    _assert_accessor(client, "load_balancers.list")
    _assert_accessor(client, "spectrum.apps.list")

    _assert_model_field(CustomHostnameListResponse, "hostname")
    _assert_model_field(LoadBalancer, "name")
    # AppListResponse is a discriminated union of these two members; the
    # collector reads `app.dns` off whichever member is returned.
    _assert_model_field(SpectrumConfigAppConfig, "dns")
    _assert_model_field(SpectrumConfigPaygoAppConfig, "dns")
    _assert_model_field(DNS, "name")  # app.dns.name


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
