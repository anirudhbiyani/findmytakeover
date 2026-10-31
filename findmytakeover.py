#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _collect_dns_records(dns_config):
    """Collect DNS records from all configured providers."""
    records = []

    for provider, config in dns_config.items():
        if provider not in _SUPPORTED_PROVIDERS:
            click.echo(
                f"The DNS provider '{provider}' is not supported. Please read the documentation."
            )
            continue

        provider_name = _PROVIDER_NAMES[provider]
        try:
            collector = _get_collector(provider)
            data = collector.dns(config["accounts"], config["credentials"], **config.get("options", {}))
        except Exception as e:
            # One broken provider shouldn't cost the others' results.
            note_error(provider_name, "(all accounts)", "DNS records", e)
            continue
        # Rows are [account, name, value] or, for MX/SRV/TXT, [account, name, value, type].
        provider_records = [
            [provider_name, item[0], item[1], item[2], item[3] if len(item) > 3 else ""]
            for item in data
        ]
        click.echo(f"Collected {len(provider_records)} DNS record(s) from {provider_name}")
        records.extend(provider_records)

    click.echo(f"Total DNS records collected: {len(records)}")
    return records


def _collect_infrastructure(infra_config):
    """Collect infrastructure data from all configured providers."""
    infrastructure = []

    for provider, config in infra_config.items():
        if provider not in _SUPPORTED_PROVIDERS:
            click.echo(
                f"The Infrastructure provider '{provider}' is not supported. Please read the documentation."
            )
            continue

        provider_name = _PROVIDER_NAMES[provider]
        try:
            collector = _get_collector(provider)
            data = collector.infra(config["accounts"], config["credentials"], **config.get("options", {}))
        except Exception as e:
            note_error(provider_name, "(all accounts)", "infrastructure", e)
            continue
        provider_infra = [
            [provider_name, item[0], item[1], item[2]] for item in data
        ]
        click.echo(f"Collected {len(provider_infra)} infrastructure resource(s) from {provider_name}")
        infrastructure.extend(provider_infra)

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


def _make_resolver():
    """Build a dnspython resolver with short, bounded timeouts so a slow or
    blackholed name can never hang the run."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_QUERY_TIMEOUT
    resolver.lifetime = _DNS_LIFETIME
    return resolver


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
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_resolve_hostname_status, resolver, h): h for h in unique}
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
    parser.add_argument("--version", action="version", version=f"findmytakeover {_version()}")

    args = parser.parse_args()
    webhooks = args.alert_webhook + os.environ.get("FINDMYTAKEOVER_ALERT_WEBHOOKS", "").split()

    # Read the baseline before spending minutes scanning, so a bad path fails fast.
    baseline = _load_baseline(args.baseline) if args.baseline else None

    click.echo(f"Reading the config from file - {args.config_file}")
    dns_config, infra_config, exclusions = read_config(args.config_file)

    # Collect data
    record_list = _collect_dns_records(dns_config)
    infrastructure_list = _collect_infrastructure(infra_config)

    # Create DataFrames
    records_df = pd.DataFrame(
        record_list, columns=["csp", "account", "dnskey", "dnsvalue", "rtype"]
    )
    infrastructure_df = pd.DataFrame(
        infrastructure_list, columns=["csp", "account", "service", "value"]
    )

    # Dump data if requested
    if args.dump_file:
        click.echo(f"Dumping data to file - {args.dump_file}")
        # Overwrite: appending mixed every earlier run's inventory into this one.
        infrastructure_df.to_csv(args.dump_file, mode="w", index=False)
        with open(args.dump_file, "a") as f:
            f.write("-" * 100 + "\n")
        records_df.to_csv(args.dump_file, mode="a", index=False)

    # Find dangling records
    if not dns_config or not infra_config:
        click.echo(
            "To check for dangling domains, both DNS and Infrastructure providers need to be configured."
        )
        return

    click.echo("Checking for possible dangling DNS records!")

    result = _find_dangling_records(records_df, infrastructure_df, exclusions)

    # Group dangling records by the provider that owns the target resource,
    # hiding internal/private ones (not takeover risks). External (third-party)
    # targets are set aside for SaaS fingerprinting below.
    grouped = {label: [] for label in _TARGET_ORDER if label != "External"}
    external_entries = []
    secondary_entries = []  # third-party MX/SRV/SPF targets, reported only if NXDOMAIN
    findings = []
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

        type_tag = f"{'SPF include' if rtype == 'TXT' else rtype} " if rtype else ""
        line = (
            f"  {name} -> {type_tag}{value} "
            f"[{result.loc[idx, 'csp_x']} zone, account/subscription/project: {result.loc[idx, 'account_x']}]"
        )
        label = _classify_target(value)

        # One structured record per finding, shared with the JSON output. The
        # External tiering below mutates these same dicts, so console and JSON
        # can never disagree.
        finding = {
            "record": str(name).rstrip("."),
            "record_type": rtype or None,
            "target": str(value).rstrip("."),
            "dns_provider": str(result.loc[idx, "csp_x"]),
            "account": str(result.loc[idx, "account_x"]),
            "target_owner": label,
            "saas_service": None,
            "dns_status": None,
            "http_status": None,
            "confidence": "inventory-miss",
        }

        # Almost every zone has an MX at a mail provider and an SPF include of
        # one; those are never in inventory. Only a target that no longer exists
        # is a finding, so hold them back until DNS has been checked.
        if rtype in SECONDARY_RECORD_TYPES and label == "External":
            finding["saas_service"] = identify_service(value)
            secondary_entries.append({"value": value, "line": line, "finding": finding})
            continue

        findings.append(finding)

        if label == "External":
            finding["saas_service"] = identify_service(value)
            external_entries.append({"value": value, "line": line, "finding": finding})
        else:
            grouped[label].append(line)

    # SaaS takeover fingerprinting + passive DNS confirmation, scoped to the
    # External bucket. Only fingerprinted hostnames (and third-party MX/SRV/SPF
    # targets) are resolved, and NXDOMAIN is the only DNS signal treated as a
    # finding.
    dns_status = {}
    hostnames_to_check = {e["value"] for e in external_entries if e["finding"]["saas_service"]}
    hostnames_to_check |= {e["value"] for e in secondary_entries}
    if hostnames_to_check:
        if not args.verify_dns:
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
    missing_secondary = []
    for entry in secondary_entries:
        finding = entry["finding"]
        status = dns_status.get(str(entry["value"]).rstrip(".").lower())
        if status != "nxdomain":
            continue
        finding["dns_status"] = status
        finding["confidence"] = "target-nxdomain"
        findings.append(finding)
        missing_secondary.append(f"{entry['line']}  [target does not exist — check whether its domain can be registered]")

    # Opt-in HTTP confirmation for fingerprinted targets DNS couldn't settle:
    # most SaaS providers wildcard their DNS, but serve a recognisable
    # "no such site" page for a hostname nobody has claimed.
    http_status = {}
    if args.verify_http:
        to_fetch = {
            e["finding"]["record"]: http_fingerprint(e["finding"]["saas_service"])
            for e in external_entries
            if e["finding"]["saas_service"]
            and http_fingerprint(e["finding"]["saas_service"])
            and dns_status.get(str(e["value"]).rstrip(".").lower()) != "nxdomain"
        }
        if to_fetch:
            click.echo(f"Fetching {len(to_fetch)} subdomain(s) over HTTP to match takeover fingerprints...")
            http_status = _verify_http_targets(to_fetch)

    takeover_candidates = []  # (a) fingerprinted + confirmed NXDOMAIN
    fingerprinted_unconfirmed = []  # (b) fingerprinted, still resolving or DNS status unknown
    unclassified_external = []  # (c) no known SaaS fingerprint
    for entry in external_entries:
        finding = entry["finding"]
        service = finding["saas_service"]
        if not service:
            unclassified_external.append(entry["line"])
            finding["confidence"] = "unclassified-third-party"
            continue

        status = dns_status.get(str(entry["value"]).rstrip(".").lower())
        finding["dns_status"] = status
        finding["http_status"] = http_status.get(finding["record"])
        if status == "nxdomain":
            takeover_candidates.append(f"{entry['line']}  [{service} — NXDOMAIN, likely claimable]")
            finding["confidence"] = "high"
        elif finding["http_status"] == "matched":
            takeover_candidates.append(f"{entry['line']}  [{service} — unclaimed-site page served, likely claimable]")
            finding["confidence"] = "high"
        elif status == "resolves":
            fingerprinted_unconfirmed.append(f"{entry['line']}  [{service} — still resolving]")
            finding["confidence"] = "fingerprinted-still-resolving"
        elif status == "unknown":
            fingerprinted_unconfirmed.append(f"{entry['line']}  [{service} — DNS status unknown]")
            finding["confidence"] = "fingerprinted-dns-unknown"
        else:
            fingerprinted_unconfirmed.append(f"{entry['line']}  [{service} — DNS check skipped]")
            finding["confidence"] = "fingerprinted-unverified"

    dangling_count = (
        sum(len(v) for v in grouped.values())
        + len(takeover_candidates)
        + len(fingerprinted_unconfirmed)
        + len(unclassified_external)
        + len(missing_secondary)
    )

    if dangling_count == 0:
        click.echo("No dangling DNS records found!")
    else:
        for label in _TARGET_ORDER:
            if label == "External":
                continue
            entries = grouped[label]
            if not entries:
                continue
            click.echo(f"\n=== Targets on {label} ({len(entries)}) ===")
            for line in entries:
                click.echo(line)

        external_total = len(takeover_candidates) + len(fingerprinted_unconfirmed) + len(unclassified_external)
        if external_total:
            click.echo(f"\n=== Targets on External / third-party (SaaS, bare IPs) ({external_total}) ===")
            if takeover_candidates:
                click.echo(f"\n  --- HIGH CONFIDENCE: fingerprinted SaaS target is unclaimed ({len(takeover_candidates)}) ---")
                for line in takeover_candidates:
                    click.echo(line)
            if fingerprinted_unconfirmed:
                click.echo(f"\n  --- Fingerprinted SaaS target, not confirmed dangling ({len(fingerprinted_unconfirmed)}) ---")
                for line in fingerprinted_unconfirmed:
                    click.echo(line)
            if unclassified_external:
                click.echo(f"\n  --- Unclassified third-party target ({len(unclassified_external)}) ---")
                for line in unclassified_external:
                    click.echo(line)

        if missing_secondary:
            click.echo(f"\n=== Mail, SRV and SPF targets that do not exist (NXDOMAIN) ({len(missing_secondary)}) ===")
            for line in missing_secondary:
                click.echo(line)

        click.echo(f"\nTotal dangling DNS records found: {dangling_count}")

    if hidden_internal:
        click.echo(
            f"\n({hidden_internal} record(s) pointing at private/internal addresses "
            "hidden \u2014 not takeover risks; use the dump file to see them)"
        )

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
        _write_json_report(args.json_file, findings, hidden_internal, COLLECTION_ERRORS, diff)

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


def _write_json_report(path, findings, hidden_internal, collection_errors=(), diff=None):
    """Write findings as JSON to a path, or to stdout when path is '-'."""
    report = {
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
    if diff is not None:
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


if __name__ == "__main__":
    main()
