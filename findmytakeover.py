#!/usr/bin/env python3

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import click
import pandas as pd
import yaml

from collector import (
    COLLECTION_ERRORS,
    MAX_WORKERS,
    SECONDARY_RECORD_TYPES,
    has_dns_suffix,
    is_aws_nameserver,
    note_error,
)
from collector.fingerprints import http_fingerprint, identify_service

# Passive DNS-resolution check (opt-out via --no-verify-dns). Optional
# dependency: degrade gracefully if dnspython isn't installed.
try:
    import dns.resolver
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False

# Per-query timeout and total-per-lookup lifetime, in seconds. Kept short so a
# blackholed/unreachable resolver can never hang the run.
_DNS_QUERY_TIMEOUT = 2.0
_DNS_LIFETIME = 5.0

# Supported cloud providers
_SUPPORTED_PROVIDERS = frozenset(("aws", "gcp", "azure", "cloudflare", "oracle"))

# Provider display names
_PROVIDER_NAMES = {
    "aws": "Amazon Web Services",
    "gcp": "Google Cloud Platform",
    "azure": "Microsoft Azure",
    "cloudflare": "Cloudflare",
    "oracle": "Oracle Cloud Infrastructure",
}

CLI_PROMPT = r"""        
    __ _           _                 _        _                            
   / _(_)         | |               | |      | |                           
  | |_ _ _ __   __| |_ __ ___  _   _| |_ __ _| | _____  _____   _____ _ __ 
  |  _| | '_ \ / _` | '_ ` _ \| | | | __/ _` | |/ / _ \/ _ \ \ / / _ \ '__|
  | | | | | | | (_| | | | | | | |_| | || (_| |   <  __/ (_) \ V /  __/ |   
  |_| |_|_| |_|\__,_|_| |_| |_|\__, |\__\__,_|_|\_\___|\___/ \_/ \___|_|   
                               __/ |                                      
                              |___/                                       
"""


def read_config(config_path):
    """Read and validate the configuration file."""
    try:
        with open(config_path, "rt") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        click.echo(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError:
        click.echo("Invalid YAML file!")
        sys.exit(1)

    # An empty file parses as None, a bare scalar as a string.
    if not isinstance(config, dict):
        click.echo(f"Invalid Configuration! {config_path} must contain 'dns' and 'infra' sections.")
        sys.exit(1)

    # Parse exclusions
    exclude = _parse_exclusions(config)

    # Parse DNS providers
    dns_providers = _parse_providers(config, "dns")
    if not dns_providers:
        click.echo("Invalid Configuration! At least one DNS provider needs to be enabled.")

    # Parse Infrastructure providers
    infra_providers = _parse_providers(config, "infra")
    if not infra_providers:
        click.echo("Invalid Configuration! At least one Infrastructure provider needs to be enabled.")

    return dns_providers, infra_providers, exclude


class _Exclusions:
    """Exclusion rules from config: IP networks matched by containment, domains
    matched as DNS suffixes (example.com excludes a.example.com, not
    notexample.com).

    Networks are kept as networks rather than expanded to individual addresses —
    expanding even the README's own 100.1.0.0/16 example produced 65,536 entries,
    each of which then cost a separate full scan of the results frame.
    """

    def __init__(self, networks=(), domains=()):
        self.networks = list(networks)
        self.domains = {str(d) for d in domains}

    def __bool__(self):
        return bool(self.networks or self.domains)

    def matches(self, value):
        """True if this DNS value is excluded."""
        text = str(value).rstrip(".")
        if self.networks:
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                pass
            else:
                return any(address in network for network in self.networks)
        return any(has_dns_suffix(text, domain) for domain in self.domains)


def _parse_exclusions(config):
    """Parse exclusion rules from config."""
    if "exclude" not in config:
        return _Exclusions()

    try:
        exclude_config = config["exclude"] or {}

        # Accepts IPv4 and IPv6 CIDRs alike; ip_network picks the right family.
        networks = [
            ipaddress.ip_network(str(entry), strict=False)
            for entry in exclude_config.get("ipaddress", []) or []
        ]
        domains = exclude_config.get("domains", []) or []

    except (KeyError, ValueError) as e:
        click.echo(f"Invalid exclusion configuration: {e}")
        sys.exit(1)

    return _Exclusions(networks, domains)


def _parse_providers(config, section):
    """Parse provider configuration from a config section."""
    providers = {}

    if section not in config:
        click.echo(f"Invalid Configuration! Please check that {section} provider is configured.")
        return providers

    try:
        for provider_name, provider_config in config[section].items():
            # An empty provider block (e.g. "aws:" with nothing under it) parses
            # as None — treat it as disabled rather than crashing on .get().
            if not provider_config or not provider_config.get("enabled"):
                continue

            credentials = provider_config.get("credentials")
            accounts = provider_config.get("accounts")

            if credentials is None:
                raise KeyError(f"Missing credentials for {provider_name}")

            use_default = isinstance(credentials, str) and credentials.strip().lower() == "default"
            if not use_default and not accounts:
                raise KeyError(f"Missing accounts for {provider_name} (required when not using 'default' credentials)")

            # Sovereign-cloud selection. AWS needs no option: the partition
            # follows the profile's region (us-gov-west-1 → aws-us-gov).
            options = {}
            if provider_config.get("cloud"):
                if provider_name != "azure":
                    raise KeyError(f"'cloud' is only supported for azure, not {provider_name}")
                options["cloud"] = provider_config["cloud"]

            providers[provider_name] = {
                "credentials": credentials,
                "accounts": accounts,
                "options": options,
            }

    except KeyError as e:
        click.echo(f"Invalid Configuration! Please check the {section} section: {e}")
        sys.exit(1)

    return providers


def _collect(section, kind):
    """Run every configured provider's `kind` collector ("dns" or "infra")
    concurrently and return {provider: rows}. Providers are independent, so
    the section takes as long as its slowest provider, not their sum."""
    noun = "DNS records" if kind == "dns" else "infrastructure"

    def run(provider, config):
        provider_name = _PROVIDER_NAMES[provider]
        started = time.monotonic()
        try:
            collector = _get_collector(provider)
            rows = getattr(collector, kind)(
                config["accounts"], config["credentials"], **config.get("options", {})
            )
        except Exception as e:
            # One broken provider shouldn't cost the others' results.
            note_error(provider_name, "(all accounts)", noun, e)
            return provider_name, []
        unit = "DNS record(s)" if kind == "dns" else "infrastructure resource(s)"
        click.echo(
            f"Collected {len(rows)} {unit} from {provider_name} "
            f"in {time.monotonic() - started:.1f}s"
        )
        return provider_name, rows

    providers = []
    for provider, config in section.items():
        if provider in _SUPPORTED_PROVIDERS:
            providers.append((provider, config))
        else:
            click.echo(f"The provider '{provider}' is not supported. Please read the documentation.")
    if not providers:
        return {}
    with ThreadPoolExecutor(max_workers=len(providers)) as pool:
        return dict(pool.map(lambda p: run(*p), providers))


def _collect_dns_records(dns_config):
    """Collect DNS records from all configured providers."""
    # Rows are [account, name, value] or, for MX/SRV/TXT, [account, name, value, type].
    records = [
        [provider_name, item[0], item[1], item[2], item[3] if len(item) > 3 else ""]
        for provider_name, rows in _collect(dns_config, "dns").items()
        for item in rows
    ]
    click.echo(f"Total DNS records collected: {len(records)}")
    return records


def _collect_infrastructure(infra_config):
    """Collect infrastructure data from all configured providers."""
    infrastructure = [
        [provider_name, item[0], item[1], item[2]]
        for provider_name, rows in _collect(infra_config, "infra").items()
        for item in rows
    ]
    click.echo(f"Total infrastructure resources collected: {len(infrastructure)}")
    return infrastructure


def _get_collector(provider):
    """Lazily import and return the collector for a provider."""
    if provider == "aws":
        from collector.aws import aws
        return aws
    elif provider == "gcp":
        from collector.gcp import gcp
        return gcp
    elif provider == "azure":
        from collector.msazure import azure
        return azure
    elif provider == "cloudflare":
        from collector.cloudflare import cloudflare
        return cloudflare
    elif provider == "oracle":
        from collector.oracle import oracle
        return oracle


_INTERNAL_SUFFIXES = (".svc.cluster.local", ".local", ".internal")


def _is_internal_record(name, value):
    """True for records that can't be a public takeover target: internal DNS
    names (K8s cluster DNS etc.) or values that are private/reserved IPs."""
    if str(name).rstrip(".").lower().endswith(_INTERNAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(str(value).rstrip("."))
    except ValueError:
        return False
    return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local


# Signatures that map a DNS record's target (value) to the provider that owns it.
_TARGET_SIGNATURES = (
    ("Amazon Web Services", (
        "amazonaws.com", "cloudfront.net", "acm-validations.aws",
        "awsdns", "awsglobalaccelerator.com", "elasticbeanstalk.com",
        "amazoncognito.com",
    )),
    ("Microsoft Azure", (
        "azure.com", "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
        "azurewebsites.net", "trafficmanager.net", "azurefd.net", "azureedge.net",
        "windows.net", "azurecr.io", "azurestaticapps.net", "azurecontainerapps.io",
        # Azure Government
        "azure.us", "azuregov-dns.us", "usgovcloudapi.net", "azurewebsites.us",
        "usgovtrafficmanager.net", "azurecr.us", "azurefd.us",
    )),
    ("Google Cloud Platform", (
        "googleapis.com", "googledomains.com", "appspot.com", "run.app",
        "cloudfunctions.net", "goog", "googleusercontent.com",
    )),
)

# Print order for the grouped report.
_TARGET_ORDER = (
    "Amazon Web Services",
    "Microsoft Azure",
    "Google Cloud Platform",
    "External",
)


def _classify_target(value):
    """Which provider owns the resource a record points at (External = SaaS/third-party or a bare IP)."""
    v = str(value).rstrip(".").lower()
    # Azure ALIAS records resolve to an ARM resource id rather than a hostname,
    # so none of the hostname signatures below can match one. Without this an
    # ALIAS finding is filed under third-party SaaS, which is plainly wrong.
    if v.startswith("/subscriptions/") and "/providers/microsoft." in v:
        return "Microsoft Azure"
    for label, suffixes in _TARGET_SIGNATURES:
        if any(
            is_aws_nameserver(v) if suffix == "awsdns" else has_dns_suffix(v, suffix)
            for suffix in suffixes
        ):
            return label
    return "External"


# Public resolvers that must agree before an NXDOMAIN counts. The system
# resolver may sit behind split-horizon DNS (a VPN, a corporate resolver) that
# answers NXDOMAIN for names that exist on the internet. Override with
# FINDMYTAKEOVER_CONFIRM_RESOLVERS (comma-separated); empty disables.
_CONFIRM_RESOLVERS = ("1.1.1.1", "8.8.8.8")


def _make_resolver(nameserver=None):
    """Build a dnspython resolver with short, bounded timeouts so a slow or
    blackholed name can never hang the run. Uses the system resolver unless
    a nameserver is given."""
    if nameserver:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
    else:
        resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_QUERY_TIMEOUT
    resolver.lifetime = _DNS_LIFETIME
    return resolver


def _confirm_resolvers():
    configured = os.environ.get("FINDMYTAKEOVER_CONFIRM_RESOLVERS")
    names = _CONFIRM_RESOLVERS if configured is None else [n.strip() for n in configured.split(",") if n.strip()]
    return [_make_resolver(n) for n in names]


def _checked_status(resolver, confirmers, hostname):
    """_resolve_hostname_status, made robust: an inconclusive answer is retried
    once, and an NXDOMAIN is overruled if any public resolver finds the name.
    A public resolver that can't be reached doesn't veto (some networks block
    outbound DNS), so the result then rests on the system resolver alone."""
    status = _resolve_hostname_status(resolver, hostname)
    if status == "unknown":
        status = _resolve_hostname_status(resolver, hostname)
    if status == "nxdomain" and any(
        _resolve_hostname_status(r, hostname) == "resolves" for r in confirmers
    ):
        return "resolves"
    return status


def _resolve_hostname_status(resolver, hostname):
    """Classify a hostname's DNS resolution as one of:

      "nxdomain" - the name doesn't exist -- for a fingerprinted SaaS target
                   this means the slot is free and the subdomain is likely
                   claimable. High confidence.
      "resolves" - the name still resolves (or exists but has no A record) --
                   still occupied, not currently a finding.
      "unknown"  - timeout, SERVFAIL, unreachable nameservers, or any other
                   resolver error. Inconclusive -- never treat as a finding.
    """
    key = str(hostname).rstrip(".").lower()
    try:
        resolver.resolve(key, "A")
        return "resolves"
    except dns.resolver.NXDOMAIN:
        return "nxdomain"
    except dns.resolver.NoAnswer:
        # The name exists (e.g. AAAA/CNAME only, no A record) -- not dangling.
        return "resolves"
    except Exception:
        # dns.exception.Timeout, dns.resolver.NoNameservers, LifetimeTimeout,
        # or anything else the resolver can throw -- treat as inconclusive
        # rather than guessing.
        return "unknown"


def _verify_dns_targets(hostnames):
    """Resolve each unique hostname at most once, in parallel, to confirm
    whether a fingerprinted SaaS target is NXDOMAIN. Returns
    {hostname: "nxdomain"|"resolves"|"unknown"}. Never raises; returns {} if
    dnspython isn't available or there's nothing to check."""
    if not _DNSPYTHON_AVAILABLE or not hostnames:
        return {}

    unique = sorted({str(h).rstrip(".").lower() for h in hostnames})
    resolver = _make_resolver()
    confirmers = _confirm_resolvers()
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_checked_status, resolver, confirmers, h): h for h in unique}
        for future in as_completed(futures):
            hostname = futures[future]
            try:
                results[hostname] = future.result()
            except Exception:
                results[hostname] = "unknown"
    return results


# Any S3 endpoint hostname: bucket.s3.amazonaws.com, bucket.s3.us-east-1.amazonaws.com,
# bucket.s3-website-us-east-1.amazonaws.com, bucket.s3.dualstack.us-gov-west-1.amazonaws.com.
# Bucket names may contain dots (website buckets are named after the site), so
# the bucket is everything before the last ".s3" label.
# The endpoint labels are matched as [a-z0-9]+ runs split by "." or "-" so the
# two can't both claim a "-": overlapping them backtracks exponentially.
_S3_HOSTNAME = re.compile(r"^(?P<bucket>.+)\.s3(?:[.-][a-z0-9]+)*\.amazonaws\.com$")


def _match_key(value):
    """Canonical form a DNS value and an inventory value are compared in.

    Route 53 alias targets come back as "dualstack.my-lb.us-east-1.elb.amazonaws.com."
    while the ELB API says "my-lb.us-east-1.elb.amazonaws.com"; DNS is
    case-insensitive; an IPv6 address has many spellings; and S3 inventory
    holds bucket names, not the endpoint hostnames records point at.
    """
    key = str(value).strip().rstrip(".").lower().removeprefix("dualstack.")
    try:
        return ipaddress.ip_address(key).compressed
    except ValueError:
        pass
    s3 = _S3_HOSTNAME.match(key)
    return s3.group("bucket") if s3 else key


_HTTP_TIMEOUT = 5.0
_HTTP_MAX_BYTES = 256 * 1024


def _http_fingerprint_status(session, hostname, pattern):
    """Fetch a subdomain and classify it as "matched" (the provider's unclaimed
    page), "no-match" (something else is served) or "unknown" (no response).

    TLS isn't verified: an unclaimed hostname usually serves the provider's
    certificate, and only the response body is read — nothing is sent.
    """
    for scheme in ("https", "http"):
        try:
            with session.get(
                f"{scheme}://{hostname}",
                timeout=_HTTP_TIMEOUT,
                verify=False,
                allow_redirects=True,
                stream=True,
            ) as response:
                body = response.raw.read(_HTTP_MAX_BYTES, decode_content=True)
        except Exception:
            continue
        text = body.decode(response.encoding or "utf-8", errors="replace")
        return "matched" if re.search(pattern, text) else "no-match"
    return "unknown"


def _verify_http_targets(patterns):
    """Fetch each {hostname: fingerprint regex} in parallel. Never raises."""
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.headers["User-Agent"] = f"findmytakeover/{_version()}"
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(_http_fingerprint_status, session, host, pattern): host
            for host, pattern in patterns.items()
        }
        for future in as_completed(futures):
            try:
                results[futures[future]] = future.result()
            except Exception:
                results[futures[future]] = "unknown"
    return results


def _find_dangling_records(records_df, infrastructure_df, exclusions):
    """Find DNS records that don't have matching infrastructure."""
    if "rtype" not in records_df:
        records_df = records_df.assign(rtype="")
    infrastructure_df = infrastructure_df.assign(
        _key=infrastructure_df["value"].map(_match_key)
    ).drop_duplicates("_key")
    result = pd.merge(
        records_df.assign(_key=records_df["dnsvalue"].map(_match_key)),
        infrastructure_df,
        on="_key",
        how="left",
    ).drop(columns="_key").fillna(value="")

    # Apply exclusions in a single vectorized pass. Accepts a plain iterable of
    # substring patterns too, so callers (and tests) predating _Exclusions work.
    if not isinstance(exclusions, _Exclusions):
        exclusions = _Exclusions(domains=exclusions or ())
    if exclusions:
        result = result[~result["dnsvalue"].map(exclusions.matches)]

    return result


def _version():
    """Version of the installed package, falling back to pyproject.toml so the
    flag still reports something useful when running from a source checkout."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("findmytakeover")
    except (ImportError, PackageNotFoundError):
        pass

    try:
        import tomllib

        pyproject = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pyproject.toml")
        with open(pyproject, "rb") as handle:
            return tomllib.load(handle)["project"]["version"]
    except (ImportError, OSError, KeyError):
        return "unknown"


def scan(dns_config, infra_config, exclusions=None, verify_dns=True, verify_http=False, dump_file=None):
    """Collect DNS and inventory, diff them and classify every dangling record.

    The library entry point: takes the output of read_config() and returns
    {"findings": [...], "hidden_internal": int, "collection_errors": [...]},
    the same findings the --json report carries. Progress still goes to the
    console.
    """
    COLLECTION_ERRORS.clear()  # errors belong to this scan, not an earlier one
    started = time.monotonic()
    # DNS and inventory don't depend on each other: collect both at once.
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = pool.submit(_collect_dns_records, dns_config)
        infrastructure = pool.submit(_collect_infrastructure, infra_config)
        records_df = pd.DataFrame(
            records.result(), columns=["csp", "account", "dnskey", "dnsvalue", "rtype"]
        )
        infrastructure_df = pd.DataFrame(
            infrastructure.result(), columns=["csp", "account", "service", "value"]
        )
    click.echo(f"Collection took {time.monotonic() - started:.1f}s")

    if dump_file:
        click.echo(f"Dumping data to file - {dump_file}")
        # Overwrite: appending mixed every earlier run's inventory into this one.
        infrastructure_df.to_csv(dump_file, mode="w", index=False)
        with open(dump_file, "a") as f:
            f.write("-" * 100 + "\n")
        records_df.to_csv(dump_file, mode="a", index=False)

    click.echo("Checking for possible dangling DNS records!")
    result = _find_dangling_records(records_df, infrastructure_df, exclusions or _Exclusions())

    findings = []
    external = []  # third-party targets, tiered by SaaS fingerprinting below
    secondary = []  # third-party MX/SRV/SPF targets, reported only if NXDOMAIN
    hidden_internal = 0
    for idx in result.index:
        if result.loc[idx, "value"] != "":
            continue

        name = result.loc[idx, "dnskey"]
        value = result.loc[idx, "dnsvalue"]
        rtype = result.loc[idx, "rtype"]
        if _is_internal_record(name, value):
            hidden_internal += 1
            continue

        label = _classify_target(value)
        finding = {
            "record": str(name).rstrip("."),
            "record_type": rtype or None,
            "target": str(value).rstrip("."),
            "dns_provider": str(result.loc[idx, "csp_x"]),
            "account": str(result.loc[idx, "account_x"]),
            "target_owner": label,
            "saas_service": identify_service(value) if label == "External" else None,
            "dns_status": None,
            "http_status": None,
            "confidence": "inventory-miss",
        }

        # Almost every zone has an MX at a mail provider and an SPF include of
        # one; those are never in inventory. Only a target that no longer exists
        # is a finding, so hold them back until DNS has been checked.
        if rtype in SECONDARY_RECORD_TYPES and label == "External":
            secondary.append(finding)
            continue

        findings.append(finding)
        if label == "External":
            external.append(finding)

    # SaaS takeover fingerprinting + passive DNS confirmation, scoped to
    # third-party targets. Only fingerprinted hostnames (and MX/SRV/SPF
    # targets) are resolved, and NXDOMAIN is the only DNS signal treated as a
    # finding.
    dns_status = {}
    hostnames_to_check = {f["target"] for f in external if f["saas_service"]}
    hostnames_to_check |= {f["target"] for f in secondary}
    if hostnames_to_check:
        if not verify_dns:
            click.echo("\nDNS verification disabled (--no-verify-dns); skipping NXDOMAIN checks on SaaS, mail and SPF targets.")
        elif not _DNSPYTHON_AVAILABLE:
            click.echo(
                "\nDNS verification requested but the 'dnspython' package isn't installed "
                "(pip install dnspython); skipping NXDOMAIN checks on SaaS, mail and SPF targets."
            )
        else:
            click.echo(f"\nResolving {len(hostnames_to_check)} third-party hostname(s) to check for NXDOMAIN...")
            dns_status = _verify_dns_targets(hostnames_to_check)

    # MX/SRV/SPF targets: a third-party target that doesn't exist means mail
    # or SPF is pointed at a name someone may be able to register.
    for finding in secondary:
        if dns_status.get(finding["target"].lower()) == "nxdomain":
            finding["dns_status"] = "nxdomain"
            finding["confidence"] = "target-nxdomain"
            findings.append(finding)

    # Opt-in HTTP confirmation for fingerprinted targets DNS couldn't settle:
    # most SaaS providers wildcard their DNS, but serve a recognisable
    # "no such site" page for a hostname nobody has claimed.
    http_status = {}
    if verify_http:
        to_fetch = {
            f["record"]: http_fingerprint(f["saas_service"])
            for f in external
            if f["saas_service"]
            and http_fingerprint(f["saas_service"])
            and dns_status.get(f["target"].lower()) != "nxdomain"
        }
        if to_fetch:
            click.echo(f"Fetching {len(to_fetch)} subdomain(s) over HTTP to match takeover fingerprints...")
            http_status = _verify_http_targets(to_fetch)

    for finding in external:
        if not finding["saas_service"]:
            finding["confidence"] = "unclassified-third-party"
            continue
        status = dns_status.get(finding["target"].lower())
        finding["dns_status"] = status
        finding["http_status"] = http_status.get(finding["record"])
        if status == "nxdomain" or finding["http_status"] == "matched":
            finding["confidence"] = "high"
        elif status == "resolves":
            finding["confidence"] = "fingerprinted-still-resolving"
        elif status == "unknown":
            finding["confidence"] = "fingerprinted-dns-unknown"
        else:
            finding["confidence"] = "fingerprinted-unverified"

    return {
        "findings": findings,
        "hidden_internal": hidden_internal,
        "collection_errors": list(COLLECTION_ERRORS),
    }


# Console notes for the third-party tiers, keyed by confidence.
_EXTERNAL_TIERS = (
    ("HIGH CONFIDENCE: fingerprinted SaaS target is unclaimed", ("high",)),
    ("Fingerprinted SaaS target, not confirmed dangling", (
        "fingerprinted-still-resolving", "fingerprinted-dns-unknown", "fingerprinted-unverified",
    )),
    ("Unclassified third-party target", ("unclassified-third-party",)),
)
_TIER_NOTES = {
    "fingerprinted-still-resolving": "still resolving",
    "fingerprinted-dns-unknown": "DNS status unknown",
    "fingerprinted-unverified": "DNS check skipped",
}


def _finding_line(f):
    kind = f.get("record_type") or ""
    type_tag = f"{'SPF include' if kind == 'TXT' else kind} " if kind else ""
    line = (
        f"  {f['record']} -> {type_tag}{f['target']} "
        f"[{f['dns_provider']} zone, account/subscription/project: {f['account']}]"
    )
    service = f.get("saas_service")
    if f["confidence"] == "high":
        why = "NXDOMAIN" if f.get("dns_status") == "nxdomain" else "unclaimed-site page served"
        line += f"  [{service} — {why}, likely claimable]"
    elif f["confidence"] in _TIER_NOTES:
        line += f"  [{service} — {_TIER_NOTES[f['confidence']]}]"
    elif f["confidence"] == "target-nxdomain":
        line += "  [target does not exist — check whether its domain can be registered]"
    return line


def _print_findings(findings, hidden_internal):
    """Console report: cloud-owned targets by provider, then third-party tiers,
    then mail/SRV/SPF targets that don't exist."""
    if not findings:
        click.echo("No dangling DNS records found!")
    else:
        for label in _TARGET_ORDER:
            entries = [f for f in findings if f["target_owner"] == label and f["confidence"] == "inventory-miss"]
            if entries:
                click.echo(f"\n=== Targets on {label} ({len(entries)}) ===")
                for f in entries:
                    click.echo(_finding_line(f))

        external = [f for f in findings if f["target_owner"] == "External" and f["confidence"] != "target-nxdomain"]
        if external:
            click.echo(f"\n=== Targets on External / third-party (SaaS, bare IPs) ({len(external)}) ===")
            for title, levels in _EXTERNAL_TIERS:
                tier = [f for f in external if f["confidence"] in levels]
                if tier:
                    click.echo(f"\n  --- {title} ({len(tier)}) ---")
                    for f in tier:
                        click.echo(_finding_line(f))

        missing = [f for f in findings if f["confidence"] == "target-nxdomain"]
        if missing:
            click.echo(f"\n=== Mail, SRV and SPF targets that do not exist (NXDOMAIN) ({len(missing)}) ===")
            for f in missing:
                click.echo(_finding_line(f))

        click.echo(f"\nTotal dangling DNS records found: {len(findings)}")

    if hidden_internal:
        click.echo(
            f"\n({hidden_internal} record(s) pointing at private/internal addresses "
            "hidden — not takeover risks; use the dump file to see them)"
        )


def main():
    click.secho(CLI_PROMPT, bold=True, fg="green")

    parser = argparse.ArgumentParser(
        description="Find dangling DNS records that may be vulnerable to subdomain takeover"
    )
    parser.add_argument(
        "-c", "--config-file",
        default=os.path.join(os.getcwd(), "findmytakeover.config"),
        type=str,
        help="Path to the configuration file",
    )
    parser.add_argument(
        "-d", "--dump-file",
        type=str,
        help="Path to save DNS and Infrastructure data",
    )
    parser.add_argument(
        "--verify-dns",
        dest="verify_dns",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Resolve third-party SaaS targets that match a known takeover "
            "fingerprint, and third-party MX/SRV/SPF targets, to confirm "
            "NXDOMAIN dangling records (requires the dnspython package). Use "
            "--no-verify-dns to disable network lookups entirely."
        ),
    )
    parser.add_argument(
        "--json",
        dest="json_file",
        type=str,
        help=(
            "Write findings as JSON to this path, for feeding a SIEM, ticketing "
            "system or dashboard. Use '-' for stdout."
        ),
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=(
            "Exit with status 1 when dangling records are found, so a CI job or "
            "scheduled scan fails instead of passing silently. Off by default so "
            "existing scripts keep their exit codes."
        ),
    )
    parser.add_argument(
        "--verify-http",
        action="store_true",
        help=(
            "Fetch fingerprinted SaaS subdomains over HTTP(S) and match the "
            "provider's 'no such site' page, confirming takeovers that DNS can't "
            "(most SaaS providers wildcard their DNS). Off by default: it sends "
            "requests to your subdomains."
        ),
    )
    parser.add_argument(
        "--baseline",
        metavar="JSON_FILE",
        help=(
            "A previous --json report. Findings are marked new or already known, "
            "fixed ones are listed as resolved, and --fail-on-findings only fails "
            "on new findings. A missing file counts as an empty baseline (first run)."
        ),
    )
    parser.add_argument(
        "--fail-on-incomplete",
        action="store_true",
        help=(
            "Exit with status 2 when part of the scan couldn't be collected (a "
            "denied API, an unreachable account), unless status 1 already applies."
        ),
    )
    parser.add_argument(
        "--alert-webhook",
        metavar="URL",
        action="append",
        default=[],
        help=(
            "POST an alert to this webhook when there's something to act on "
            "(repeatable). Slack incoming webhooks get a Slack message; any other "
            "URL gets JSON. Prefer the FINDMYTAKEOVER_ALERT_WEBHOOKS environment "
            "variable (space-separated) so URLs stay out of process lists and CI logs."
        ),
    )
    parser.add_argument(
        "--alert-confidence",
        default=",".join(_DEFAULT_ALERT_CONFIDENCE),
        help=(
            "Comma-separated confidence levels that alert, or 'all' "
            f"(default: {','.join(_DEFAULT_ALERT_CONFIDENCE)}). With --baseline "
            "only new findings alert."
        ),
    )
    parser.add_argument(
        "--json-format",
        choices=("findmytakeover", "ocsf", "defectdojo"),
        default="findmytakeover",
        help=(
            "Format of the --json output: the native report (default), OCSF 1.3 "
            "Detection Findings for SIEMs and data lakes, or DefectDojo's generic "
            "findings import."
        ),
    )
    parser.add_argument(
        "--security-hub",
        action="store_true",
        help=(
            "Import findings into AWS Security Hub in the current AWS session's "
            "account and region. With --baseline, resolved findings are archived."
        ),
    )
    parser.add_argument(
        "--terraform-plan",
        metavar="PLAN_JSON",
        help=(
            "Instead of scanning, check a plan from 'terraform show -json': exit 1 "
            "if applying it would leave a DNS record (in the plan, or live via the "
            "config's DNS providers when the config exists) pointing at a resource "
            "it destroys."
        ),
    )
    parser.add_argument("--version", action="version", version=f"findmytakeover {_version()}")

    args = parser.parse_args()
    webhooks = args.alert_webhook + os.environ.get("FINDMYTAKEOVER_ALERT_WEBHOOKS", "").split()

    # Read the baseline before spending minutes scanning, so a bad path fails fast.
    baseline = _load_baseline(args.baseline) if args.baseline else None

    if args.terraform_plan:
        sys.exit(_terraform_guard(args))

    click.echo(f"Reading the config from file - {args.config_file}")
    dns_config, infra_config, exclusions = read_config(args.config_file)
    result = scan(
        dns_config, infra_config, exclusions,
        verify_dns=args.verify_dns, verify_http=args.verify_http, dump_file=args.dump_file,
    )
    findings, hidden_internal = result["findings"], result["hidden_internal"]
    _print_findings(findings, hidden_internal)

    if COLLECTION_ERRORS:
        click.echo(
            f"\nWARNING: the scan is incomplete \u2014 {len(COLLECTION_ERRORS)} collection error(s). "
            "Missing inventory shows up as false positives above; missing DNS data hides real findings."
        )
        for (provider, what, error), count in _summarise_errors(COLLECTION_ERRORS):
            suffix = f" (x{count})" if count > 1 else ""
            click.echo(f"  {provider} {what}: {error}{suffix}")

    diff = None
    if baseline is not None:
        diff = _compare_with_baseline(findings, baseline)
        click.echo(
            f"\n=== Compared with baseline {args.baseline}: "
            f"{len(diff['new'])} new, {len(diff['resolved'])} resolved ==="
        )
        for label, items in (("New", diff["new"]), ("Resolved", diff["resolved"])):
            for f in items:
                click.echo(f"  {label}: {f['record']} -> {f['target']} [{f['target_owner']}, {f['confidence']}]")
        if COLLECTION_ERRORS and diff["resolved"]:
            click.echo("  (this scan is incomplete, so some 'resolved' findings may just be unscanned)")

    if args.json_file:
        _write_json_report(args.json_file, findings, hidden_internal, COLLECTION_ERRORS, diff, args.json_format)

    if args.security_hub:
        _send_to_security_hub(findings, diff["resolved"] if diff else ())

    if webhooks:
        alert = _build_alert(
            diff["new"] if diff else findings, args.alert_confidence, COLLECTION_ERRORS
        )
        if alert:
            _send_alerts(webhooks, alert)

    sys.exit(_exit_code(args, len(diff["new"]) if diff else len(findings), bool(COLLECTION_ERRORS)))


# Confidence levels worth interrupting someone for. The fingerprinted-but-
# unconfirmed and unclassified tiers are a worklist for the report, not alerts.
_DEFAULT_ALERT_CONFIDENCE = ("high", "inventory-miss", "target-nxdomain")
_ALERT_LIST_LIMIT = 20
_ALERT_TIMEOUT = 10.0


def _build_alert(candidates, confidence_filter, collection_errors):
    """What an alert should say, or None when there's nothing to act on.

    `candidates` are the findings eligible to alert (new ones with --baseline);
    an incomplete scan alerts on its own, because it silently weakens every
    other result.
    """
    wanted = {c.strip() for c in str(confidence_filter).split(",") if c.strip()}
    findings = [f for f in candidates if "all" in wanted or f["confidence"] in wanted]
    if not findings and not collection_errors:
        return None
    return {
        "tool": "findmytakeover",
        "version": _version(),
        "findings": findings,
        "complete": not collection_errors,
        "collection_errors": [
            {"provider": p, "what": w, "error": e, "count": n}
            for (p, w, e), n in _summarise_errors(collection_errors)
        ],
    }


def _alert_text(alert):
    """Plain-text rendering of an alert, used for Slack."""
    lines = []
    findings = alert["findings"]
    if findings:
        lines.append(f"*findmytakeover: {len(findings)} dangling DNS record(s) to act on*")
        for f in findings[:_ALERT_LIST_LIMIT]:
            via = f.get("saas_service") or f["target_owner"]
            kind = f"{f['record_type']} " if f.get("record_type") else ""
            lines.append(f"• `{f['record']}` → {kind}`{f['target']}` ({via}, {f['confidence']})")
        if len(findings) > _ALERT_LIST_LIMIT:
            lines.append(f"…and {len(findings) - _ALERT_LIST_LIMIT} more (see the JSON report)")
    if not alert["complete"]:
        lines.append("*Scan incomplete* — results may contain false positives and miss findings:")
        for e in alert["collection_errors"][:_ALERT_LIST_LIMIT]:
            count = f" (x{e['count']})" if e["count"] > 1 else ""
            lines.append(f"• {e['provider']} {e['what']}: {e['error']}{count}")
    return "\n".join(lines)


def _alert_payload(url, alert):
    """Slack incoming webhooks need {"text": ...}; anything else gets the alert as JSON."""
    if urlparse(url).hostname == "hooks.slack.com":
        return {"text": _alert_text(alert)}
    return alert


def _send_alerts(webhooks, alert, session=None):
    """POST the alert to every webhook. A failed delivery is reported but never
    changes the exit status: the findings are already in the report."""
    if session is None:
        import requests

        session = requests.Session()
    for url in webhooks:
        host = urlparse(url).hostname or "webhook"  # never print the URL: it's a secret
        try:
            response = session.post(url, json=_alert_payload(url, alert), timeout=_ALERT_TIMEOUT)
            response.raise_for_status()
            click.echo(f"Alert sent to {host}.")
        except Exception as e:
            click.echo(f"Warning: alert to {host} failed - {type(e).__name__}")


def _exit_code(args, failing_findings, incomplete):
    """0 = clean; 1 = findings (new ones, with --baseline) and --fail-on-findings;
    2 = incomplete scan and --fail-on-incomplete. Both are opt-in so existing
    callers keep exit status 0."""
    if args.fail_on_findings and failing_findings:
        return 1
    if args.fail_on_incomplete and incomplete:
        return 2
    return 0


def _finding_key(finding):
    """What makes two runs' findings the same finding: the record, its type and
    where it points. Confidence and DNS status may change between runs."""
    return (
        str(finding.get("record", "")).rstrip(".").lower(),
        finding.get("record_type") or "",
        str(finding.get("target", "")).rstrip(".").lower(),
    )


def _load_baseline(path):
    """Findings from an earlier --json report. A missing file is an empty
    baseline (the first scheduled run); an unreadable one is an error, because
    silently treating it as empty would re-alert on everything."""
    try:
        with open(path) as handle:
            report = json.load(handle)
    except FileNotFoundError:
        click.echo(f"Baseline {path} not found; treating every finding as new.")
        return []
    except (OSError, ValueError) as e:
        click.echo(f"Could not read baseline {path}: {e}")
        sys.exit(1)
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        click.echo(f"Baseline {path} is not a findmytakeover --json report.")
        sys.exit(1)
    return report["findings"]


def _compare_with_baseline(findings, baseline):
    """Mark each finding new or known (sets finding["new"]) and return
    {"new": [...], "resolved": [baseline findings no longer present]}."""
    known = {_finding_key(f) for f in baseline}
    current = {_finding_key(f) for f in findings}
    for finding in findings:
        finding["new"] = _finding_key(finding) not in known
    return {
        "new": [f for f in findings if f["new"]],
        "resolved": [f for f in baseline if _finding_key(f) not in current],
    }


def _summarise_errors(errors):
    """Group identical failures (the same denied API in every region) into one line each."""
    counts = {}
    for e in errors:
        key = (e["provider"], e["what"], e["error"])
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items())


def _write_json_report(path, findings, hidden_internal, collection_errors=(), diff=None, fmt="findmytakeover"):
    """Write findings as JSON to a path, or to stdout when path is '-'. `fmt`
    picks the native report, OCSF Detection Findings or DefectDojo's generic
    import format."""
    report = _export(fmt, findings) if fmt != "findmytakeover" else {
        "tool": "findmytakeover",
        "version": _version(),
        "summary": {
            "total": len(findings),
            "high_confidence": sum(1 for f in findings if f["confidence"] == "high"),
            "hidden_internal": hidden_internal,
            "by_target_owner": {
                owner: sum(1 for f in findings if f["target_owner"] == owner)
                for owner in sorted({f["target_owner"] for f in findings})
            },
            "complete": not collection_errors,
        },
        "collection_errors": list(collection_errors),
        "findings": findings,
    }
    if diff is not None and fmt == "findmytakeover":
        report["summary"]["new"] = len(diff["new"])
        report["summary"]["resolved"] = len(diff["resolved"])
        report["resolved"] = diff["resolved"]

    if path == "-":
        click.echo(json.dumps(report, indent=2))
        return

    try:
        with open(path, "w") as handle:
            json.dump(report, handle, indent=2)
    except OSError as e:
        click.echo(f"Could not write JSON report to {path}: {e}")
        sys.exit(1)

    click.echo(f"\nJSON report written to {path} ({len(findings)} finding(s))")


# --- Export formats ---------------------------------------------------------

# Severity by confidence: how likely the record can be claimed today.
_SEVERITY = {
    "high": "High",
    "inventory-miss": "Medium",
    "target-nxdomain": "Medium",
    "fingerprinted-still-resolving": "Low",
    "fingerprinted-dns-unknown": "Low",
    "fingerprinted-unverified": "Low",
    "unclassified-third-party": "Info",
}
_OCSF_SEVERITY_ID = {"Info": 1, "Low": 2, "Medium": 3, "High": 4}
_REMEDIATION = (
    "Delete the DNS record, or point it back at a resource you own. Re-check the "
    "record first: it may have been fixed since the scan."
)


def _finding_uid(finding):
    """Stable id across runs (same key as the baseline), so SIEMs and Security
    Hub update a finding instead of duplicating it."""
    return hashlib.sha256("|".join(_finding_key(finding)).encode()).hexdigest()[:32]


def _finding_title(f):
    kind = f"{f['record_type']} " if f.get("record_type") else ""
    return f"Dangling DNS record {f['record']} -> {kind}{f['target']}"


def _finding_description(f):
    via = f.get("saas_service") or f["target_owner"]
    return (
        f"{f['record']} points at {f['target']} ({via}), which was not found in any scanned "
        f"account (confidence: {f['confidence']}). DNS zone: {f['dns_provider']} {f['account']}."
    )


def _ocsf_finding(f, now):
    """OCSF 1.3 Detection Finding (class 2004)."""
    severity = _SEVERITY.get(f["confidence"], "Info")
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 200401,
        "severity_id": _OCSF_SEVERITY_ID[severity],
        "severity": severity,
        "status_id": 1,
        "status": "New",
        "time": int(now.timestamp() * 1000),
        "message": _finding_title(f),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "findmytakeover", "vendor_name": "findmytakeover", "version": _version()},
        },
        "finding_info": {
            "uid": _finding_uid(f),
            "title": _finding_title(f),
            "desc": _finding_description(f),
            "types": ["Dangling DNS", "Subdomain Takeover"],
        },
        "resources": [{"name": f["record"], "type": "DNS Record", "uid": f["record"]}],
        "cloud": {"provider": f["dns_provider"], "account": {"uid": f["account"]}},
        "remediation": {"desc": _REMEDIATION},
        "unmapped": f,
    }


def _defectdojo_finding(f, now):
    """DefectDojo 'Generic Findings Import' format."""
    return {
        "title": _finding_title(f),
        "description": _finding_description(f),
        "severity": _SEVERITY.get(f["confidence"], "Info"),
        "date": now.strftime("%Y-%m-%d"),
        "mitigation": _REMEDIATION,
        "component_name": f["record"],
        "unique_id_from_tool": _finding_uid(f),
        "vuln_id_from_tool": f["confidence"],
        "active": True,
        "verified": f["confidence"] == "high",
    }


def _export(fmt, findings):
    now = datetime.now(timezone.utc)
    if fmt == "ocsf":
        return [_ocsf_finding(f, now) for f in findings]
    return {"findings": [_defectdojo_finding(f, now) for f in findings]}


def _asff_finding(f, account, region, partition, now, archived=False):
    """AWS Security Finding Format, imported as the account's own (default) product."""
    severity = _SEVERITY.get(f["confidence"], "Info").upper()
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"findmytakeover/{_finding_uid(f)}",
        "ProductArn": f"arn:{partition}:securityhub:{region}:{account}:product/{account}/default",
        "GeneratorId": "findmytakeover",
        "AwsAccountId": account,
        "Types": ["Software and Configuration Checks/Vulnerabilities"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": "INFORMATIONAL" if severity == "INFO" else severity},
        "Title": _finding_title(f)[:256],
        "Description": _finding_description(f)[:1024],
        "Remediation": {"Recommendation": {"Text": _REMEDIATION}},
        "Resources": [{
            "Type": "Other",
            "Id": f["record"],
            "Details": {"Other": {
                k: str(f.get(k) or "")[:1024]
                for k in ("target", "record_type", "confidence", "dns_provider", "account", "target_owner")
            }},
        }],
        "RecordState": "ARCHIVED" if archived else "ACTIVE",
    }
    return finding


def _send_to_security_hub(findings, resolved=(), session=None):
    """Import findings into Security Hub in the current AWS session's account
    and region; resolved ones (from --baseline) are archived. Failures are
    reported but never change the exit status."""
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        session = session or boto3.Session()
        region = session.region_name
        if not region:
            click.echo("Security Hub: no AWS region configured (set AWS_REGION); skipping.")
            return
        account = session.client("sts", region_name=region).get_caller_identity()["Account"]
        partition = session.get_partition_for_region(region)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        batch = [_asff_finding(f, account, region, partition, now) for f in findings]
        batch += [_asff_finding(f, account, region, partition, now, archived=True) for f in resolved]
        client = session.client("securityhub", region_name=region)
        failed = 0
        for i in range(0, len(batch), 100):  # API limit: 100 findings per call
            failed += client.batch_import_findings(Findings=batch[i:i + 100])["FailedCount"]
        click.echo(f"Security Hub: imported {len(batch) - failed} finding(s) into {account}/{region}, {failed} failed.")
    except (BotoCoreError, ClientError) as e:
        click.echo(f"Warning: Security Hub import failed - {e}")


# --- Terraform plan guard -----------------------------------------------------

# Resource types that are DNS records. Their values are what can dangle;
# everything else in the plan is a potential target.
_TF_DNS_RECORD_TYPES = frozenset((
    "aws_route53_record",
    "google_dns_record_set",
    "azurerm_dns_a_record", "azurerm_dns_aaaa_record", "azurerm_dns_cname_record",
    "azurerm_dns_mx_record", "azurerm_dns_ns_record", "azurerm_dns_srv_record",
    "azurerm_dns_txt_record",
    "cloudflare_record", "cloudflare_dns_record",
    "oci_dns_rrset", "oci_dns_record",
))
# Top-level record attributes that name the record rather than point anywhere.
_TF_RECORD_NAME_KEYS = frozenset((
    "id", "name", "fqdn", "type", "ttl", "zone_id", "zone_name", "managed_zone",
    "resource_group_name", "project", "zone_name_or_id", "comment", "tags", "tags_all",
))


def _tf_strings(value):
    """Every string leaf in a plan value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _tf_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _tf_strings(v)


def _tf_record(rc, values):
    name = values.get("fqdn") or values.get("hostname") or values.get("name") or rc["address"]
    rtype = values.get("type") or rc["type"].removeprefix("azurerm_dns_").removesuffix("_record").upper()
    targets = _tf_strings({k: v for k, v in values.items() if k not in _TF_RECORD_NAME_KEYS})
    return str(name), str(rtype), targets


def _terraform_dangling(plan, live_records=()):
    """DNS records that would dangle once `plan` (terraform show -json) applies:
    a record, kept by the plan or live in DNS, whose value is an endpoint of a
    resource the plan destroys and doesn't recreate at the same address.

    Endpoints are matched generically: every string in the destroyed
    resource's state (hostnames, IPs, bucket names, name servers) is a
    candidate, so new resource types need no code.
    # ponytail: generic string match; per-type endpoint attributes if it ever
    # produces noise.
    """
    destroyed, kept, records, deleted_records = {}, set(), [], set()
    for rc in plan.get("resource_changes", []):
        change = rc.get("change", {})
        actions = change.get("actions", [])
        before, after = change.get("before") or {}, change.get("after") or {}
        if rc.get("type") in _TF_DNS_RECORD_TYPES:
            if actions == ["delete"]:
                name, rtype, _ = _tf_record(rc, before)
                deleted_records.add((name.rstrip(".").lower(), rtype))
            elif after:
                name, rtype, targets = _tf_record(rc, after)
                records += [("terraform", rc["address"], name, t, rtype) for t in targets]
            continue
        if "delete" in actions:
            for s in _tf_strings(before):
                if "." in s or ":" in s:
                    destroyed.setdefault(_match_key(s), rc["address"])
        kept.update(_match_key(s) for s in _tf_strings(after))

    findings = []
    for source, where, name, target, rtype in [*records, *live_records]:
        if (str(name).rstrip(".").lower(), rtype) in deleted_records:
            continue  # the plan removes this record too
        key = _match_key(target)
        if key in destroyed and key not in kept:
            findings.append({
                "record": str(name).rstrip("."),
                "record_type": rtype,
                "target": str(target).rstrip("."),
                "source": f"{source} {where}",
                "destroyed_by": destroyed[key],
            })
    return findings


def _terraform_guard(args):
    """--terraform-plan: fail (exit 1) if applying the plan leaves DNS dangling."""
    try:
        with open(args.terraform_plan) as handle:
            plan = json.load(handle)
    except (OSError, ValueError) as e:
        click.echo(f"Could not read Terraform plan {args.terraform_plan}: {e}")
        return 1

    live = []
    if os.path.exists(args.config_file):
        click.echo(f"Reading live DNS using {args.config_file}")
        dns_config, _, _ = read_config(args.config_file)
        live = _collect_dns_records(dns_config)
    else:
        click.echo("No config file; checking only the DNS records in the plan.")

    findings = _terraform_dangling(plan, live)
    for f in findings:
        click.echo(
            f"  {f['record']} -> {f['record_type']} {f['target']} "
            f"[{f['source']}] would dangle: {f['destroyed_by']} is destroyed"
        )
    click.echo(
        f"\n{len(findings)} DNS record(s) would dangle after this plan."
        if findings else "No DNS record would dangle after this plan."
    )
    if args.json_file:
        payload = {"tool": "findmytakeover", "version": _version(), "findings": findings}
        if args.json_file == "-":
            click.echo(json.dumps(payload, indent=2))
        else:
            with open(args.json_file, "w") as handle:
                json.dump(payload, handle, indent=2)
    return 1 if findings else 0


if __name__ == "__main__":
    main()
