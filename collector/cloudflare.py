#!/usr/bin/env python3

from cloudflare import Cloudflare, APIError
import click

from collector import is_cloud_nameserver, zone_key

_RELEVANT_RECORD_TYPES = frozenset(("A", "AAAA", "CNAME"))
_USE_CLI_CREDS = "default"


def _is_default_credentials(cred):
    return isinstance(cred, str) and cred.strip().lower() == _USE_CLI_CREDS


def _client(cred):
    """Cloudflare client. 'default' reads CLOUDFLARE_API_TOKEN from the env; otherwise cred is the API token."""
    if _is_default_credentials(cred):
        return Cloudflare()
    return Cloudflare(api_token=cred)


def _resolve_accounts(accounts, client, use_default):
    """Account ids to scan, auto-discovered from the token when using default creds."""
    if not use_default or accounts:
        return accounts
    discovered = [account.id for account in client.accounts.list()]
    click.echo(f"Auto-discovered {len(discovered)} Cloudflare account(s) from API token")
    return discovered


class cloudflare:
    @staticmethod
    def dns(accounts, cred):
        """Collect DNS records from Cloudflare zones."""
        client = _client(cred)
        accounts = _resolve_accounts(accounts, client, _is_default_credentials(cred))
        dnsdata = []

        for account in accounts:
            click.echo(f"Reading DNS data from Cloudflare account - {account}")
            try:
                for zone in client.zones.list(account={"id": account}):
                    # Cloudflare returns one record object per NS value, so group
                    # nameservers by delegated name and emit each delegation once.
                    ns_by_name = {}
                    for record in client.dns.records.list(zone_id=zone.id):
                        name = record.name
                        content = record.content or ""

                        if record.type in _RELEVANT_RECORD_TYPES:
                            value = content.rstrip(".") if record.type == "CNAME" else content
                            if value:
                                dnsdata.append([account, name, value])
                        elif record.type == "NS" and zone_key(name) != zone_key(zone.name):
                            ns_by_name.setdefault(name, []).append(content)

                    # Child NS delegation to a cloud NS pool → dangling if the
                    # delegated zone is not in the inventory (see infra()).
                    for name, nameservers in ns_by_name.items():
                        if any(is_cloud_nameserver(ns) for ns in nameservers):
                            dnsdata.append([account, name, zone_key(name)])
            except APIError as e:
                click.echo(f"Skipping Cloudflare account {account} - API error: {e}")

        return dnsdata

    @staticmethod
    def infra(accounts, cred):
        """Collect Cloudflare-hosted endpoints (zone names for NS matching, Pages)."""
        client = _client(cred)
        accounts = _resolve_accounts(accounts, client, _is_default_credentials(cred))
        infradata = []

        for account in accounts:
            click.echo(f"Getting Infrastructure details from Cloudflare account - {account}")
            try:
                # Zone names — the "live zones" a delegated NS record is matched against.
                for zone in client.zones.list(account={"id": account}):
                    infradata.append([account, "hostedzone", zone_key(zone.name)])

                # Cloudflare Pages (*.pages.dev subdomain + custom domains)
                for project in client.pages.projects.list(account_id=account):
                    if project.subdomain:
                        infradata.append([account, "pages", project.subdomain.rstrip(".")])
                    for domain in (project.domains or []):
                        infradata.append([account, "pages", str(domain).rstrip(".")])
            except APIError as e:
                click.echo(f"Skipping Cloudflare account {account} - API error: {e}")

        # ponytail: Workers/Spectrum hostnames not collected — add if a CNAME to
        # *.workers.dev shows up as a false positive.
        return infradata
