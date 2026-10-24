#!/usr/bin/env python3
"""Shared helpers for the cloud collectors."""

import os

# Collectors are network-I/O bound, so fan out per-account/region/project work
# across threads. Tune with FINDMYTAKEOVER_MAX_WORKERS if you hit API rate limits.
# ponytail: fixed pool size; raise the env var if throttling isn't a concern.
MAX_WORKERS = max(1, int(os.environ.get("FINDMYTAKEOVER_MAX_WORKERS", "8")))

# Nameserver suffixes for the managed-DNS pools where a deleted zone can be
# re-registered by someone else — the dangling-NS-delegation takeover case. A
# delegation to a provider we don't inventory (a registrar, another managed DNS
# host) stays out of scope: we can't tell from inventory alone whether it's live.
_CLOUD_NS_SUFFIXES = (
    "azure-dns.com",        # Microsoft Azure DNS
    "azure-dns.net",
    "azure-dns.org",
    "azure-dns.info",
    "googledomains.com",    # Google Cloud DNS
    "cloud.goog",           # Google Cloud DNS (alternate pool)
    "ns.cloudflare.com",    # Cloudflare
    "dns.oraclecloud.net",  # Oracle Cloud Infrastructure DNS
)


def is_aws_nameserver(nsdname):
    """True for Route 53 nameserver hostnames, not arbitrary names containing aws tokens."""
    labels = str(nsdname).rstrip(".").lower().split(".")
    if len(labels) not in (3, 4):
        return False
    if not labels[0].startswith("ns-") or not labels[0][3:].isdigit():
        return False
    if not labels[1].startswith("awsdns-") or not labels[1][7:].isdigit():
        return False
    return tuple(labels[2:]) in {("com",), ("net",), ("org",), ("co", "uk")}


def is_cloud_nameserver(nsdname):
    """True if a nameserver belongs to a takeover-prone managed-DNS pool."""
    value = str(nsdname).rstrip(".").lower()
    return is_aws_nameserver(value) or any(
        value == suffix or value.endswith("." + suffix)
        for suffix in _CLOUD_NS_SUFFIXES
    )


def zone_key(name):
    """Normalize a DNS/zone name or resource id for matching (drop trailing dot, lowercase)."""
    return str(name).rstrip(".").lower()
