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
        """Collect Cloudflare-hosted endpoints: zones, Pages, Workers, R2, Custom
        Hostnames, Load Balancers, Spectrum, and Tunnels."""
        client = _client(cred)
        accounts = _resolve_accounts(accounts, client, _is_default_credentials(cred))
        infradata = []

        for account in accounts:
            click.echo(f"Getting Infrastructure details from Cloudflare account - {account}")

            # Zone names — the "live zones" a delegated NS record is matched against.
            # Also the basis for the per-zone endpoint types collected below.
            try:
                zones = list(client.zones.list(account={"id": account}))
            except APIError as e:
                click.echo(f"Skipping Cloudflare account {account} - API error listing zones: {e}")
                continue

            for zone in zones:
                infradata.append([account, "hostedzone", zone_key(zone.name)])

            # Cloudflare Pages (*.pages.dev subdomain + custom domains)
            try:
                for project in client.pages.projects.list(account_id=account):
                    if project.subdomain:
                        infradata.append([account, "pages", zone_key(project.subdomain)])
                    for domain in (project.domains or []):
                        infradata.append([account, "pages", zone_key(str(domain))])
            except APIError as e:
                click.echo(f"Skipping Cloudflare Pages for account {account} - API error: {e}")

            # Workers: workers.dev subdomain (per-script) + custom domains bound to a Worker.
            try:
                account_subdomain = None
                try:
                    account_subdomain = client.workers.subdomains.get(account_id=account).subdomain
                except APIError:
                    pass  # workers.dev subdomain not configured for this account

                if account_subdomain:
                    for script in client.workers.scripts.list(account_id=account):
                        if script.id:
                            hostname = f"{script.id}.{account_subdomain}.workers.dev"
                            infradata.append([account, "workers", zone_key(hostname)])

                for domain in client.workers.domains.list(account_id=account):
                    if domain.hostname:
                        infradata.append([account, "workers", zone_key(domain.hostname)])
            except APIError as e:
                click.echo(f"Skipping Cloudflare Workers for account {account} - API error: {e}")

            # R2 buckets: public r2.dev domain + any custom domains attached to the bucket.
            try:
                buckets = client.r2.buckets.list(account_id=account).buckets or []
                for bucket in buckets:
                    if not bucket.name:
                        continue
                    try:
                        managed = client.r2.buckets.domains.managed.list(
                            bucket_name=bucket.name, account_id=account
                        )
                        if managed.domain:
                            infradata.append([account, "r2", zone_key(managed.domain)])
                    except APIError:
                        pass  # r2.dev public access not enabled/permitted for this bucket

                    try:
                        custom = client.r2.buckets.domains.custom.list(
                            bucket_name=bucket.name, account_id=account
                        )
                        for custom_domain in (custom.domains or []):
                            if custom_domain.domain:
                                infradata.append([account, "r2", zone_key(custom_domain.domain)])
                    except APIError:
                        pass  # no custom domains configured/permitted for this bucket
            except APIError as e:
                click.echo(f"Skipping Cloudflare R2 for account {account} - API error: {e}")

            # Tunnels: CNAME/target hostname is <tunnel-uuid>.cfargotunnel.com
            try:
                for tunnel in client.zero_trust.tunnels.cloudflared.list(account_id=account):
                    if tunnel.id:
                        hostname = f"{tunnel.id}.cfargotunnel.com"
                        infradata.append([account, "tunnel", zone_key(hostname)])
            except APIError as e:
                click.echo(f"Skipping Cloudflare Tunnels for account {account} - API error: {e}")

            # Per-zone endpoint types: Custom Hostnames (Cloudflare for SaaS),
            # Load Balancers, and Spectrum applications.
            for zone in zones:
                try:
                    for hostname in client.custom_hostnames.list(zone_id=zone.id):
                        if hostname.hostname:
                            infradata.append([account, "customhostname", zone_key(hostname.hostname)])
                except APIError as e:
                    click.echo(f"Skipping Custom Hostnames for zone {zone.name} - API error: {e}")

                try:
                    for lb in client.load_balancers.list(zone_id=zone.id):
                        if lb.name:
                            infradata.append([account, "loadbalancer", zone_key(lb.name)])
                except APIError as e:
                    click.echo(f"Skipping Load Balancers for zone {zone.name} - API error: {e}")

                try:
                    for app in client.spectrum.apps.list(zone_id=zone.id):
                        dns = getattr(app, "dns", None)
                        if dns is not None and dns.name:
                            infradata.append([account, "spectrum", zone_key(dns.name)])
                except APIError as e:
                    click.echo(f"Skipping Spectrum apps for zone {zone.name} - API error: {e}")

        return infradata
