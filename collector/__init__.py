#!/usr/bin/env python3
"""Shared helpers for the cloud collectors."""

import os

import click

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
    "azuregov-dns.us",      # Microsoft Azure Government DNS
    "googledomains.com",    # Google Cloud DNS
    "cloud.goog",           # Google Cloud DNS (alternate pool)
    "ns.cloudflare.com",    # Cloudflare
    "dns.oraclecloud.net",  # Oracle Cloud Infrastructure DNS
)

# Collection failures that left a gap in the inventory or the DNS data. A gap
# in inventory turns live records into false positives; a gap in DNS hides
# real findings. Either way the report has to say the scan was incomplete.
# list.append is atomic, so collector threads can record into it directly.
COLLECTION_ERRORS = []


def note_error(provider, scope, what, error):
    """Record (and print) a collection failure that didn't abort the run."""
    message = str(error).splitlines()[0] if str(error) else type(error).__name__
    COLLECTION_ERRORS.append(
        {"provider": provider, "scope": str(scope), "what": what, "error": message}
    )
    click.echo(f"Warning: could not collect {what} for {provider} {scope} - {message}")


def has_dns_suffix(hostname, suffix):
    """True if `hostname` is `suffix` or ends in it at a DNS label boundary."""
    hostname = str(hostname).rstrip(".").lower()
    suffix = str(suffix).rstrip(".").lower()
    return hostname == suffix or hostname.endswith("." + suffix)


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
    return is_aws_nameserver(nsdname) or any(
        has_dns_suffix(nsdname, suffix) for suffix in _CLOUD_NS_SUFFIXES
    )


# Record types whose targets are hostnames that aren't web endpoints: a mail
# exchanger, a service target, or a domain an SPF policy delegates to. These
# are reported only when the target no longer exists (see findmytakeover.py),
# so the usual "MX points at Google" doesn't drown out real findings.
SECONDARY_RECORD_TYPES = frozenset(("MX", "SRV", "TXT"))


def secondary_targets(rtype, rdata):
    """Hostnames referenced by an MX, SRV or SPF TXT record's presentation-format rdata.

    MX "10 mx.example.com." and SRV "1 10 5060 sip.example.com." name their
    target last. A TXT record only counts when it's an SPF policy, whose
    include:/redirect= mechanisms name the domains allowed to send mail.
    """
    text = str(rdata).strip()
    if rtype in ("MX", "SRV"):
        target = text.split()[-1].rstrip(".").lower() if text else ""
        # A null MX/SRV target (".") means "no service here" — nothing to check.
        return [target] if target else []
    if rtype == "TXT":
        # TXT rdata arrives quoted and possibly split into 255-byte chunks.
        policy = "".join(part for part in text.split('"') if part.strip()).strip()
        if not policy.lower().startswith("v=spf1"):
            return []
        targets = []
        for term in policy.split()[1:]:
            term = term.lstrip("+-~?").lower()
            for prefix in ("include:", "redirect="):
                if term.startswith(prefix):
                    domain = term[len(prefix):].rstrip(".")
                    # Macro-expanded domains (%{i}...) can't be checked statically.
                    if domain and "%" not in domain:
                        targets.append(domain)
        return targets
    return []


def zone_key(name):
    """Normalize a DNS/zone name or resource id for matching (drop trailing dot, lowercase)."""
    return str(name).rstrip(".").lower()
