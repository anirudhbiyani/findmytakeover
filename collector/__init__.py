#!/usr/bin/env python3
"""Shared helpers for the cloud collectors."""

# Nameserver suffixes for the managed-DNS pools where a deleted zone can be
# re-registered by someone else — the dangling-NS-delegation takeover case. A
# delegation to any other provider (registrar, Cloudflare, ...) is out of scope
# here: we can't tell from inventory alone whether it's still live.
_CLOUD_NS_SUFFIXES = ("awsdns", "azure-dns", "googledomains", "cloud.goog")


def is_cloud_nameserver(nsdname):
    """True if a nameserver belongs to a takeover-prone managed-DNS pool."""
    value = str(nsdname).lower()
    return any(suffix in value for suffix in _CLOUD_NS_SUFFIXES)


def zone_key(name):
    """Normalize a DNS/zone name or resource id for matching (drop trailing dot, lowercase)."""
    return str(name).rstrip(".").lower()
