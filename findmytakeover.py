#!/usr/bin/env python3

import argparse
import ipaddress
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import click
import pandas as pd
import yaml

from collector import MAX_WORKERS
from collector.fingerprints import identify_service

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


def _parse_exclusions(config):
    """Parse exclusion rules from config."""
    exclude = set()

    if "exclude" not in config:
        return exclude

    try:
        exclude_config = config["exclude"]

        # Expand IP networks to individual addresses
        for ip_network in exclude_config.get("ipaddress", []):
            for ip in ipaddress.IPv4Network(ip_network):
                exclude.add(str(ip))

        # Add domain exclusions
        for domain in exclude_config.get("domains", []):
            exclude.add(str(domain))

    except (KeyError, ValueError) as e:
        click.echo(f"Invalid exclusion configuration: {e}")
        sys.exit(1)

    return exclude


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

            providers[provider_name] = {
                "credentials": credentials,
                "accounts": accounts,
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
        collector = _get_collector(provider)

        data = collector.dns(config["accounts"], config["credentials"])
        provider_records = [
            [provider_name, item[0], item[1], item[2]] for item in data
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
        collector = _get_collector(provider)

        data = collector.infra(config["accounts"], config["credentials"])
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
    )),
    ("Microsoft Azure", (
        "azure.com", "azure-dns.", "azurewebsites.net", "trafficmanager.net",
        "azurefd.net", "azureedge.net", "cloudapp.azure.com", "core.windows.net",
        "azurecr.io", "search.windows.net", "cache.windows.net",
        "database.windows.net", "azurestaticapps.net", "azurecontainerapps.io",
    )),
    ("Google Cloud Platform", (
        "googleapis.com", "googledomains.com", "appspot.com", "run.app",
        "cloudfunctions.net", ".goog", "googleusercontent.com",
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
    for label, needles in _TARGET_SIGNATURES:
        if any(n in v for n in needles):
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


def _find_dangling_records(records_df, infrastructure_df, exclusions):
    """Find DNS records that don't have matching infrastructure."""
    result = pd.merge(
        records_df,
        infrastructure_df,
        left_on="dnsvalue",
        right_on="value",
        how="left",
    ).fillna(value="")

    # Apply exclusions
    for exclusion in exclusions:
        result = result[~result["dnsvalue"].str.contains(exclusion, na=False, regex=False)]

    return result


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
            "fingerprint to confirm NXDOMAIN dangling records (requires the "
            "dnspython package). Use --no-verify-dns to disable network "
            "lookups entirely."
        ),
    )

    args = parser.parse_args()

    click.echo(f"Reading the config from file - {args.config_file}")
    dns_config, infra_config, exclusions = read_config(args.config_file)

    # Collect data
    record_list = _collect_dns_records(dns_config)
    infrastructure_list = _collect_infrastructure(infra_config)

    # Create DataFrames
    records_df = pd.DataFrame(
        record_list, columns=["csp", "account", "dnskey", "dnsvalue"]
    )
    infrastructure_df = pd.DataFrame(
        infrastructure_list, columns=["csp", "account", "service", "value"]
    )

    # Dump data if requested
    if args.dump_file:
        click.echo(f"Dumping data to file - {args.dump_file}")
        infrastructure_df.to_csv(args.dump_file, mode="a", index=False)
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
    hidden_internal = 0
    for idx in result.index:
        if result.loc[idx, "value"] != "":
            continue

        name = result.loc[idx, "dnskey"]
        value = result.loc[idx, "dnsvalue"]
        if _is_internal_record(name, value):
            hidden_internal += 1
            continue

        line = (
            f"  {name} -> {value} "
            f"[{result.loc[idx, 'csp_x']} zone, account/subscription/project: {result.loc[idx, 'account_x']}]"
        )
        label = _classify_target(value)
        if label == "External":
            external_entries.append({"value": value, "line": line, "service": identify_service(value)})
        else:
            grouped[label].append(line)

    # SaaS takeover fingerprinting + passive DNS confirmation, scoped to the
    # External bucket. Only fingerprinted hostnames are resolved -- this is
    # DNS-only (no HTTP) and NXDOMAIN is the only signal treated as a finding.
    dns_status = {}
    fingerprinted_hostnames = {e["value"] for e in external_entries if e["service"]}
    if fingerprinted_hostnames:
        if not args.verify_dns:
            click.echo("\nDNS verification disabled (--no-verify-dns); skipping NXDOMAIN checks on fingerprinted SaaS targets.")
        elif not _DNSPYTHON_AVAILABLE:
            click.echo(
                "\nDNS verification requested but the 'dnspython' package isn't installed "
                "(pip install dnspython); skipping NXDOMAIN checks on fingerprinted SaaS targets."
            )
        else:
            click.echo(f"\nResolving {len(fingerprinted_hostnames)} fingerprinted SaaS hostname(s) to check for NXDOMAIN...")
            dns_status = _verify_dns_targets(fingerprinted_hostnames)

    takeover_candidates = []  # (a) fingerprinted + confirmed NXDOMAIN
    fingerprinted_unconfirmed = []  # (b) fingerprinted, still resolving or DNS status unknown
    unclassified_external = []  # (c) no known SaaS fingerprint
    for entry in external_entries:
        service = entry["service"]
        if not service:
            unclassified_external.append(entry["line"])
            continue

        status = dns_status.get(str(entry["value"]).rstrip(".").lower())
        if status == "nxdomain":
            takeover_candidates.append(f"{entry['line']}  [{service} — NXDOMAIN, likely claimable]")
        elif status == "resolves":
            fingerprinted_unconfirmed.append(f"{entry['line']}  [{service} — still resolving]")
        elif status == "unknown":
            fingerprinted_unconfirmed.append(f"{entry['line']}  [{service} — DNS status unknown]")
        else:
            fingerprinted_unconfirmed.append(f"{entry['line']}  [{service} — DNS check skipped]")

    dangling_count = (
        sum(len(v) for v in grouped.values())
        + len(takeover_candidates)
        + len(fingerprinted_unconfirmed)
        + len(unclassified_external)
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
                click.echo(f"\n  --- HIGH CONFIDENCE: fingerprinted SaaS target is NXDOMAIN ({len(takeover_candidates)}) ---")
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

        click.echo(f"\nTotal dangling DNS records found: {dangling_count}")

    if hidden_internal:
        click.echo(
            f"\n({hidden_internal} record(s) pointing at private/internal addresses "
            "hidden \u2014 not takeover risks; use the dump file to see them)"
        )


if __name__ == "__main__":
    main()
