#!/usr/bin/env python3

import argparse
import ipaddress
import os
import sys

import click
import pandas as pd
import yaml

# Supported cloud providers
_SUPPORTED_PROVIDERS = frozenset(("aws", "gcp", "azure"))

# Provider display names
_PROVIDER_NAMES = {
    "aws": "Amazon Web Services",
    "gcp": "Google Cloud Platform",
    "azure": "Microsoft Azure",
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
            if not provider_config.get("enabled"):
                continue

            credentials = provider_config.get("credentials")
            accounts = provider_config.get("accounts")

            if credentials is None or accounts is None:
                raise KeyError(f"Missing credentials or accounts for {provider_name}")

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
        records.extend(
            [provider_name, item[0], item[1], item[2]] for item in data
        )

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
        infrastructure.extend(
            [provider_name, item[0], item[1], item[2]] for item in data
        )

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

    # Report dangling records
    dangling_count = 0
    for idx in result.index:
        if result.loc[idx, "value"] == "":
            dangling_count += 1
            click.echo(
                f"Found dangling DNS record - {result.loc[idx, 'dnskey']} "
                f"with value {result.loc[idx, 'dnsvalue']} "
                f"in {result.loc[idx, 'csp_x']} cloud "
                f"(account/subscription/project: {result.loc[idx, 'account_x']})"
            )

    if dangling_count == 0:
        click.echo("No dangling DNS records found!")
    else:
        click.echo(f"\nTotal dangling DNS records found: {dangling_count}")


if __name__ == "__main__":
    main()
