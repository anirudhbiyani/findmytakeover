#!/usr/bin/env python3

from azure.core.exceptions import HttpResponseError
from azure.mgmt.dns import DnsManagementClient
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.trafficmanager import TrafficManagerManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.search import SearchManagementClient
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.sql import SqlManagementClient
import click

from collector import is_cloud_nameserver, zone_key

_USE_CLI_CREDS = "default"


def _strip_protocol(url):
    """Remove https:// prefix and trailing slash from URL."""
    if not url:
        return ""
    return url.removeprefix("https://").removeprefix("http://").rstrip("/")


def _is_default_credentials(cred):
    return isinstance(cred, str) and cred.strip().lower() == _USE_CLI_CREDS


def _load_credentials(cred):
    """Return Azure credentials from explicit config or local CLI session."""
    if _is_default_credentials(cred):
        return DefaultAzureCredential()
    return ClientSecretCredential(
        cred["AZURE_TENANT_ID"],
        cred["AZURE_CLIENT_ID"],
        cred["AZURE_CLIENT_SECRET"],
    )


def _resolve_subscriptions(accounts, credentials, use_default):
    """Return the subscription list, auto-discovering via SubscriptionClient when using default credentials."""
    if not use_default:
        return accounts

    if accounts:
        return accounts

    sub_client = SubscriptionClient(credentials)
    discovered = [
        sub.subscription_id
        for sub in sub_client.subscriptions.list()
        if sub.state and str(sub.state) == "Enabled"
    ]
    click.echo(f"Auto-discovered {len(discovered)} Azure subscription(s) from CLI credentials")
    return discovered


class azure:
    @staticmethod
    def dns(accounts, cred):
        """Collect DNS records from Azure subscriptions."""
        credentials = _load_credentials(cred)
        accounts = _resolve_subscriptions(accounts, credentials, _is_default_credentials(cred))
        dnsdata = []

        for subscription in accounts:
            click.echo(f"Reading DNS data from Azure Subscription - {subscription}")

            try:
                resourcegroup_client = ResourceManagementClient(credentials, subscription)
                dns_client = DnsManagementClient(credentials, subscription)

                for rg in resourcegroup_client.resource_groups.list():
                    for zone in dns_client.zones.list_by_resource_group(
                        resource_group_name=rg.name
                    ):
                        record_sets = dns_client.record_sets.list_by_dns_zone(
                            resource_group_name=rg.name, zone_name=zone.name
                        )

                        for record in record_sets:
                            fqdn = record.fqdn.rstrip(".")

                            if record.a_records:
                                dnsdata.extend(
                                    [subscription, fqdn, r.ipv4_address]
                                    for r in record.a_records
                                )
                            elif record.aaaa_records:
                                dnsdata.extend(
                                    [subscription, fqdn, r.ipv6_address]
                                    for r in record.aaaa_records
                                )
                            elif record.cname_record:
                                dnsdata.append(
                                    [subscription, fqdn, record.cname_record.cname]
                                )
                            # ALIAS records point at an Azure resource id (Traffic
                            # Manager, Public IP, CDN, Front Door). Matched against
                            # live resource ids collected in infra().
                            elif record.target_resource and record.target_resource.id:
                                dnsdata.append(
                                    [subscription, fqdn, zone_key(record.target_resource.id)]
                                )
                            # Child NS delegation to a cloud NS pool → dangling if
                            # the delegated zone is not in the inventory.
                            elif record.ns_records and zone_key(fqdn) != zone_key(zone.name):
                                nameservers = [ns.nsdname for ns in record.ns_records]
                                if any(is_cloud_nameserver(ns) for ns in nameservers):
                                    dnsdata.append([subscription, fqdn, zone_key(fqdn)])
            except HttpResponseError as e:
                if "AuthorizationFailed" in str(e):
                    click.echo(f"Skipping subscription {subscription} - authorization failed")
                else:
                    raise

        return dnsdata

    @staticmethod
    def infra(accounts, cred):
        """Collect infrastructure data from Azure subscriptions."""
        credentials = _load_credentials(cred)
        accounts = _resolve_subscriptions(accounts, credentials, _is_default_credentials(cred))
        infradata = []

        for subscription in accounts:
            click.echo(
                f"Getting Infrastructure details from Microsoft Azure Subscription - {subscription}"
            )

            try:
                # Initialize all clients once per subscription
                clients = _create_azure_clients(credentials, subscription)

                # Azure Functions / Web Apps (subscription-wide, no need to iterate per RG)
                for app in clients["web"].web_apps.list():
                    if app.host_names:
                        infradata.append([subscription, "webapp", app.host_names[0]])

                # Static Sites (subscription-wide)
                for site in clients["web"].static_sites.list():
                    if site.default_hostname:
                        infradata.append(
                            [subscription, "staticsite", site.default_hostname]
                        )

                # Process resource groups
                for rg in clients["resource"].resource_groups.list():
                    rg_name = rg.name

                    # DNS zone names — the "live zones" a delegated NS record is
                    # matched against to spot dangling delegations.
                    for zone in clients["dns"].zones.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        infradata.append([subscription, "dnszone", zone_key(zone.name)])

                    # CDN Profiles and Endpoints
                    _collect_cdn_data(clients["cdn"], subscription, rg_name, infradata)

                    # SQL Databases
                    for server in clients["sql"].servers.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        if server.fully_qualified_domain_name:
                            infradata.append(
                                [subscription, "sql", server.fully_qualified_domain_name]
                            )

                    # Public IP Addresses
                    for ip in clients["network"].public_ip_addresses.list(
                        resource_group_name=rg_name
                    ):
                        if ip.ip_address:
                            infradata.append([subscription, "publicip", ip.ip_address])
                        if ip.id:  # resource id — target of an ALIAS record
                            infradata.append([subscription, "publicip", zone_key(ip.id)])

                    # Traffic Manager Profiles
                    for profile in clients["traffic"].profiles.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        if profile.dns_config and profile.dns_config.fqdn:
                            infradata.append(
                                [subscription, "trafficmanager", profile.dns_config.fqdn]
                            )
                        if profile.id:  # resource id — target of an ALIAS record
                            infradata.append(
                                [subscription, "trafficmanager", zone_key(profile.id)]
                            )

                    # Storage Accounts
                    _collect_storage_data(
                        clients["storage"], subscription, rg_name, infradata
                    )

                    # API Management
                    for api in clients["api"].api_management_service.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        if api.gateway_url:
                            infradata.append(
                                [
                                    subscription,
                                    "apimanagement",
                                    _strip_protocol(api.gateway_url),
                                ]
                            )
                        if api.public_ip_addresses:
                            for ip in api.public_ip_addresses:
                                infradata.append([subscription, "apimanagement", ip])

                    # Container Registry
                    for registry in clients["ecr"].registries.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        if registry.login_server:
                            infradata.append(
                                [subscription, "containerregistry", registry.login_server]
                            )

                    # Container Instances
                    for container in clients[
                        "container"
                    ].container_groups.list_by_resource_group(resource_group_name=rg_name):
                        if container.ip_address and container.ip_address.ip:
                            infradata.append(
                                [subscription, "containerinstance", container.ip_address.ip]
                            )

                    # Cognitive Search
                    for search in clients["search"].services.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        if search.name:
                            infradata.append(
                                [
                                    subscription,
                                    "cognitivesearch",
                                    f"{search.name}.search.windows.net",
                                ]
                            )

                    # Redis Cache
                    for cache in clients["redis"].redis.list_by_resource_group(
                        resource_group_name=rg_name
                    ):
                        if cache.host_name:
                            infradata.append([subscription, "redis", cache.host_name])

            except HttpResponseError as e:
                if "AuthorizationFailed" in str(e):
                    click.echo(f"Skipping subscription {subscription} - authorization failed")
                else:
                    raise

        return infradata


def _create_azure_clients(credentials, subscription):
    """Create all Azure management clients for a subscription."""
    return {
        "resource": ResourceManagementClient(credentials, subscription),
        "dns": DnsManagementClient(credentials, subscription),
        "network": NetworkManagementClient(credentials, subscription),
        "cdn": CdnManagementClient(credentials, subscription),
        "traffic": TrafficManagerManagementClient(credentials, subscription),
        "web": WebSiteManagementClient(credentials, subscription),
        "storage": StorageManagementClient(credentials, subscription),
        "api": ApiManagementClient(credentials, subscription),
        "sql": SqlManagementClient(credentials, subscription),
        "ecr": ContainerRegistryManagementClient(credentials, subscription),
        "container": ContainerInstanceManagementClient(credentials, subscription),
        "search": SearchManagementClient(credentials, subscription),
        "redis": RedisManagementClient(credentials, subscription),
    }


def _collect_cdn_data(cdn_client, subscription, rg_name, infradata):
    """Collect CDN endpoints and AFD data from a resource group."""
    for profile in cdn_client.profiles.list_by_resource_group(
        resource_group_name=rg_name
    ):
        profile_name = profile.name

        # Standard CDN endpoints
        for endpoint in cdn_client.endpoints.list_by_profile(
            resource_group_name=rg_name, profile_name=profile_name
        ):
            if endpoint.host_name:
                infradata.append([subscription, "cdn", endpoint.host_name])
            if endpoint.id:  # resource id — target of an ALIAS record
                infradata.append([subscription, "cdn", zone_key(endpoint.id)])

        # Azure Front Door endpoints
        for afd in cdn_client.afd_endpoints.list_by_profile(
            resource_group_name=rg_name, profile_name=profile_name
        ):
            if afd.host_name:
                infradata.append([subscription, "frontdoor", afd.host_name])
            if afd.id:  # resource id — target of an ALIAS record
                infradata.append([subscription, "frontdoor", zone_key(afd.id)])

        # AFD Custom Domains
        for domain in cdn_client.afd_custom_domains.list_by_profile(
            resource_group_name=rg_name, profile_name=profile_name
        ):
            if domain.host_name:
                infradata.append([subscription, "frontdoor", domain.host_name])


def _collect_storage_data(storage_client, subscription, rg_name, infradata):
    """Collect storage account endpoints from a resource group."""
    endpoint_types = ("blob", "queue", "table", "file", "web", "dfs")

    for account in storage_client.storage_accounts.list_by_resource_group(
        resource_group_name=rg_name
    ):
        # Primary endpoints
        if account.primary_endpoints:
            for ep_type in endpoint_types:
                endpoint = getattr(account.primary_endpoints, ep_type, None)
                if endpoint:
                    infradata.append(
                        [subscription, "storage", _strip_protocol(endpoint)]
                    )

        # Secondary endpoints (if geo-redundant)
        if account.secondary_endpoints:
            for ep_type in endpoint_types:
                endpoint = getattr(account.secondary_endpoints, ep_type, None)
                if endpoint:
                    infradata.append(
                        [subscription, "storage", _strip_protocol(endpoint)]
                    )
