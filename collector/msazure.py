#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor

from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.dns import DnsManagementClient
from azure.identity import AzureAuthorityHosts, ClientSecretCredential, DefaultAzureCredential
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
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.appcontainers import ContainerAppsAPIClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
import click

from collector import MAX_WORKERS, is_cloud_nameserver, note_error, secondary_targets, zone_key

_PROVIDER = "Microsoft Azure"

_USE_CLI_CREDS = "default"

# `cloud:` config value (the names `az cloud list` uses) → (login authority,
# Resource Manager endpoint). Every client and credential is pointed at both.
_CLOUDS = {
    "azurecloud": (AzureAuthorityHosts.AZURE_PUBLIC_CLOUD, "https://management.azure.com"),
    "azureusgovernment": (AzureAuthorityHosts.AZURE_GOVERNMENT, "https://management.usgovcloudapi.net"),
}


def _cloud(name):
    """Resolve a `cloud:` config value, defaulting to the public cloud."""
    key = str(name or "AzureCloud").replace(" ", "").lower()
    if key not in _CLOUDS:
        raise ValueError(f"Unknown Azure cloud {name!r}; use AzureCloud or AzureUSGovernment")
    return _CLOUDS[key]


def _arm(endpoint):
    """Client kwargs that send Resource Manager calls (and token requests) to
    `endpoint`, with timeouts well under azure-core's 5-minute defaults so a
    stalled connection is retried instead of holding a worker."""
    return {
        "base_url": endpoint,
        "credential_scopes": [f"{endpoint}/.default"],
        "connection_timeout": 10,
        "read_timeout": 120,
    }


def _resource_group(resource_id):
    """Resource group of an ARM id: /subscriptions/<s>/resourceGroups/<rg>/..."""
    return resource_id.split("/")[4]


def _strip_protocol(url):
    """Remove https:// prefix and trailing slash from URL."""
    if not url:
        return ""
    return url.removeprefix("https://").removeprefix("http://").rstrip("/")


def _secondary_rdata(record):
    """(type, presentation-format rdata) pairs for a record set's MX/SRV/TXT records."""
    for mx in record.mx_records or []:
        yield "MX", f"{mx.preference} {mx.exchange}"
    for srv in record.srv_records or []:
        yield "SRV", f"{srv.priority} {srv.weight} {srv.port} {srv.target}"
    for txt in record.txt_records or []:
        # Azure splits long TXT values into 255-byte chunks; rejoin them.
        yield "TXT", "".join(txt.value or [])


def _is_default_credentials(cred):
    return isinstance(cred, str) and cred.strip().lower() == _USE_CLI_CREDS


def _load_credentials(cred, authority):
    """Return Azure credentials from explicit config or local CLI session."""
    if _is_default_credentials(cred):
        return DefaultAzureCredential(authority=authority)
    return ClientSecretCredential(
        cred["AZURE_TENANT_ID"],
        cred["AZURE_CLIENT_ID"],
        cred["AZURE_CLIENT_SECRET"],
        authority=authority,
    )


def _resolve_subscriptions(accounts, credentials, use_default, endpoint):
    """Return the subscription list, auto-discovering via SubscriptionClient when using default credentials."""
    if not use_default:
        return accounts

    if accounts:
        return accounts

    sub_client = SubscriptionClient(credentials, **_arm(endpoint))
    discovered = [
        sub.subscription_id
        for sub in sub_client.subscriptions.list()
        if sub.state and str(sub.state) == "Enabled"
    ]
    click.echo(f"Auto-discovered {len(discovered)} Azure subscription(s) from CLI credentials")
    return discovered


class azure:
    @staticmethod
    def dns(accounts, cred, cloud=None):
        """Collect DNS records from Azure subscriptions, in parallel."""
        authority, endpoint = _cloud(cloud)
        credentials = _load_credentials(cred, authority)
        accounts = _resolve_subscriptions(accounts, credentials, _is_default_credentials(cred), endpoint)

        dnsdata = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for rows in pool.map(
                lambda sub: _dns_for_subscription(credentials, sub, endpoint), accounts
            ):
                dnsdata.extend(rows)
        return dnsdata

    @staticmethod
    def infra(accounts, cred, cloud=None):
        """Collect infrastructure data from Azure subscriptions.

        Every (subscription, resource type) is its own task, listed
        subscription-wide in one paged call rather than once per resource
        group, and a failure only costs that resource type.
        """
        authority, endpoint = _cloud(cloud)
        credentials = _load_credentials(cred, authority)
        accounts = _resolve_subscriptions(accounts, credentials, _is_default_credentials(cred), endpoint)

        clients = {}
        for subscription in accounts:
            click.echo(f"Getting Infrastructure details from Microsoft Azure Subscription - {subscription}")
            clients[subscription] = _create_azure_clients(credentials, subscription, endpoint)

        tasks = [(sub, label, collect) for sub in accounts for label, collect in _INFRA_COLLECTORS]
        infradata = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for rows in pool.map(lambda t: _run_collector(clients[t[0]], *t), tasks):
                infradata.extend(rows)
        return infradata


def _dns_for_subscription(credentials, subscription, endpoint):
    click.echo(f"Reading DNS data from Azure Subscription - {subscription}")
    dnsdata = []
    try:
        dns_client = DnsManagementClient(credentials, subscription, **_arm(endpoint))
        for zone in dns_client.zones.list():
            record_sets = dns_client.record_sets.list_by_dns_zone(
                resource_group_name=_resource_group(zone.id), zone_name=zone.name
            )
            for record in record_sets:
                fqdn = record.fqdn.rstrip(".")

                if record.a_records:
                    dnsdata.extend([subscription, fqdn, r.ipv4_address] for r in record.a_records)
                elif record.aaaa_records:
                    dnsdata.extend([subscription, fqdn, r.ipv6_address] for r in record.aaaa_records)
                elif record.cname_record:
                    dnsdata.append([subscription, fqdn, record.cname_record.cname])
                # ALIAS records point at an Azure resource id (Traffic
                # Manager, Public IP, CDN, Front Door). Matched against
                # live resource ids collected in infra().
                elif record.target_resource and record.target_resource.id:
                    dnsdata.append([subscription, fqdn, zone_key(record.target_resource.id)])
                # Child NS delegation to a cloud NS pool → dangling if
                # the delegated zone is not in the inventory.
                elif record.ns_records and zone_key(fqdn) != zone_key(zone.name):
                    nameservers = [ns.nsdname for ns in record.ns_records]
                    if any(is_cloud_nameserver(ns) for ns in nameservers):
                        dnsdata.append([subscription, fqdn, zone_key(fqdn)])
                dnsdata.extend(
                    [subscription, fqdn, target, rtype]
                    for rtype, rdata in _secondary_rdata(record)
                    for target in secondary_targets(rtype, rdata)
                )
    except AzureError as e:
        note_error(_PROVIDER, subscription, "DNS records", e)
    return dnsdata


_CLIENT_CLASSES = {
    "dns": DnsManagementClient,
    "network": NetworkManagementClient,
    "cdn": CdnManagementClient,
    "traffic": TrafficManagerManagementClient,
    "web": WebSiteManagementClient,
    "storage": StorageManagementClient,
    "api": ApiManagementClient,
    "sql": SqlManagementClient,
    "ecr": ContainerRegistryManagementClient,
    "container": ContainerInstanceManagementClient,
    "search": SearchManagementClient,
    "redis": RedisManagementClient,
    "compute": ComputeManagementClient,
    "aks": ContainerServiceClient,
    "containerapps": ContainerAppsAPIClient,
    "cosmosdb": CosmosDBManagementClient,
}


def _create_azure_clients(credentials, subscription, endpoint="https://management.azure.com"):
    """Create all Azure management clients for a subscription, all aimed at one cloud."""
    return {
        name: cls(credentials, subscription, **_arm(endpoint))
        for name, cls in _CLIENT_CLASSES.items()
    }


# A resource provider that was never registered in the subscription can't have
# any resources of that type: nothing to collect, not a gap. Anything else
# (AuthorizationFailed included) is a gap and is reported.
_UNREGISTERED_MARKER = "MissingSubscriptionRegistration"


def _run_collector(clients, subscription, label, collect):
    try:
        return [[subscription, label, value] for value in collect(clients) if value]
    except HttpResponseError as e:
        if _UNREGISTERED_MARKER in str(e):
            return []
        note_error(_PROVIDER, subscription, label, e)
    except Exception as e:
        # A gap in this one resource type; raising would cost every other
        # task in the pool its results.
        note_error(_PROVIDER, subscription, label, e)
    return []


# --- Subscription-wide collectors. Each takes the subscription's clients and
# yields endpoint values (hostnames, IPs, or zone_key'd resource ids that
# ALIAS records point at).

def _webapps(c):
    for app in c["web"].web_apps.list():
        if app.host_names:
            yield app.host_names[0]


def _static_sites(c):
    for site in c["web"].static_sites.list():
        yield site.default_hostname


def _dns_zones(c):
    # The "live zones" a delegated NS record is matched against.
    for zone in c["dns"].zones.list():
        yield zone_key(zone.name)


def _cdn_endpoints(c):
    for profile in c["cdn"].profiles.list():
        for endpoint in c["cdn"].endpoints.list_by_profile(
            resource_group_name=_resource_group(profile.id), profile_name=profile.name
        ):
            yield endpoint.host_name
            yield zone_key(endpoint.id) if endpoint.id else None


def _front_door(c):
    for profile in c["cdn"].profiles.list():
        rg = _resource_group(profile.id)
        for afd in c["cdn"].afd_endpoints.list_by_profile(resource_group_name=rg, profile_name=profile.name):
            yield afd.host_name
            yield zone_key(afd.id) if afd.id else None
        for domain in c["cdn"].afd_custom_domains.list_by_profile(resource_group_name=rg, profile_name=profile.name):
            yield domain.host_name


def _sql(c):
    for server in c["sql"].servers.list():
        yield server.fully_qualified_domain_name


def _public_ips(c):
    """Every public IP resource in the subscription. This also covers VMs,
    load balancers and application gateways: their frontends reference these
    same resources, so listing them separately added no values."""
    for ip in c["network"].public_ip_addresses.list_all():
        yield ip.ip_address
        if ip.dns_settings and ip.dns_settings.fqdn:
            yield _strip_protocol(ip.dns_settings.fqdn)  # a direct CNAME target
        yield zone_key(ip.id) if ip.id else None  # target of an ALIAS record


def _vmss_instance_ips(c):
    """Per-instance public IPs of scale sets aren't standalone resources, so
    list_all() above doesn't return them."""
    for vmss in c["compute"].virtual_machine_scale_sets.list_all():
        for ip in c["network"].public_ip_addresses.list_virtual_machine_scale_set_public_ip_addresses(
            resource_group_name=_resource_group(vmss.id), virtual_machine_scale_set_name=vmss.name
        ):
            yield ip.ip_address
            if ip.dns_settings and ip.dns_settings.fqdn:
                yield _strip_protocol(ip.dns_settings.fqdn)


def _traffic_manager(c):
    for profile in c["traffic"].profiles.list_by_subscription():
        if profile.dns_config:
            yield profile.dns_config.fqdn
        yield zone_key(profile.id) if profile.id else None  # target of an ALIAS record


_STORAGE_ENDPOINT_TYPES = ("blob", "queue", "table", "file", "web", "dfs")


def _storage(c):
    for account in c["storage"].storage_accounts.list():
        # Secondary endpoints exist for geo-redundant accounts.
        for endpoints in (account.primary_endpoints, account.secondary_endpoints):
            for ep_type in _STORAGE_ENDPOINT_TYPES:
                yield _strip_protocol(getattr(endpoints, ep_type, None) if endpoints else None)


def _api_management(c):
    for api in c["api"].api_management_service.list():
        yield _strip_protocol(api.gateway_url)
        yield from api.public_ip_addresses or []


def _container_registries(c):
    for registry in c["ecr"].registries.list():
        yield registry.login_server


def _container_instances(c):
    for group in c["container"].container_groups.list():
        if group.ip_address:
            yield group.ip_address.ip


def _search(c):
    for search in c["search"].services.list_by_subscription():
        # The endpoint differs by cloud (search.windows.net, search.azure.us),
        # so prefer the one the API reports.
        if search.endpoint:
            yield _strip_protocol(search.endpoint)
        elif search.name:
            yield f"{search.name}.search.windows.net"


def _redis(c):
    for cache in c["redis"].redis.list_by_subscription():
        yield cache.host_name


def _aks(c):
    for cluster in c["aks"].managed_clusters.list():
        yield cluster.fqdn
        yield cluster.private_fqdn


def _container_apps(c):
    for app in c["containerapps"].container_apps.list_by_subscription():
        ingress = getattr(app.configuration, "ingress", None) if app.configuration else None
        yield ingress.fqdn if ingress else None
        yield app.latest_revision_fqdn


def _cosmosdb(c):
    for account in c["cosmosdb"].database_accounts.list():
        # "https://<name>.documents.azure.com:443/" -> bare hostname.
        yield _strip_protocol(account.document_endpoint).split(":")[0]


_INFRA_COLLECTORS = (
    ("webapp", _webapps),
    ("staticsite", _static_sites),
    ("dnszone", _dns_zones),
    ("cdn", _cdn_endpoints),
    ("frontdoor", _front_door),
    ("sql", _sql),
    ("publicip", _public_ips),
    ("virtualmachine", _vmss_instance_ips),
    ("trafficmanager", _traffic_manager),
    ("storage", _storage),
    ("apimanagement", _api_management),
    ("containerregistry", _container_registries),
    ("containerinstance", _container_instances),
    ("cognitivesearch", _search),
    ("redis", _redis),
    ("aks", _aks),
    ("containerapp", _container_apps),
    ("cosmosdb", _cosmosdb),
)
