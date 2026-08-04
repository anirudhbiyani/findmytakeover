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
    "awsdns",               # AWS Route 53
    "azure-dns",            # Microsoft Azure DNS
    "googledomains",        # Google Cloud DNS
    "cloud.goog",           # Google Cloud DNS (alternate pool)
    "ns.cloudflare.com",    # Cloudflare
    "dns.oraclecloud.net",  # Oracle Cloud Infrastructure DNS
)


def is_cloud_nameserver(nsdname):
    """True if a nameserver belongs to a takeover-prone managed-DNS pool."""
    value = str(nsdname).lower()
    return any(suffix in value for suffix in _CLOUD_NS_SUFFIXES)


def zone_key(name):
    """Normalize a DNS/zone name or resource id for matching (drop trailing dot, lowercase)."""
    return str(name).rstrip(".").lower()
