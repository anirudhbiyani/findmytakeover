#!/usr/bin/env python3
"""Contract tests pinning the Azure SDK shapes collector/msazure.py depends on.

Azure is the largest collector (20 service types) and the least verified, so a
dependabot bump to an `azure-mgmt-*` package that silently renames or removes a
field/operation should fail CI here instead of quietly breaking detection in
production.

No network calls and no Azure credentials are used anywhere in this file:
everything is model instantiation and class/source introspection.

## Two traps this file deliberately avoids

1. Modern `azure-mgmt-*` models are mapping-based. Nested/flattened properties
   (e.g. `PublicIPAddress.dns_settings`) live under the ARM `properties`
   envelope server-side, so a model instance's `_attr_to_rest_field` map only
   contains the ~10 top-level envelope fields (id, name, properties, sku,
   ...) - `dns_settings` is NOT in it, even though the attribute genuinely
   exists and works. Asserting against `_attr_to_rest_field` (or
   `_attribute_map`) would produce false "missing field" failures for every
   flattened property. `hasattr()` on a constructed *instance* is what
   actually resolves the flattening machinery and is the correct surface.
   See test_trap_attr_to_rest_field_hides_flattened_fields below.

2. Client operation groups (e.g. `NetworkManagementClient().public_ip_addresses`)
   are assigned as *instance* attributes inside `__init__`, not declared on
   the class - so `hasattr(NetworkManagementClient, "public_ip_addresses")`
   is False even on a perfectly healthy SDK. Instead, for clients we (a) grep
   the client class's `__init__` source to confirm it still wires the
   attribute name to the expected `*Operations` class, and (b) hasattr-check
   the method on that operations class itself, since operation methods are
   plain functions defined at class level (no instantiation needed).
   See test_trap_class_level_hasattr_misses_operation_groups below.

Run: python -m pytest tests/test_contract_azure.py -v
"""

import inspect
import re

import pytest


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _assert_fields(instance, *fields):
    """Assert every name in `fields` exists on `instance` (via hasattr).

    Failure names the model class and the missing field so a dependabot-bump
    breakage points straight at collector/msazure.py's usage.
    """
    cls = type(instance)
    for field in fields:
        assert hasattr(instance, field), (
            f"{cls.__module__}.{cls.__qualname__} no longer has field "
            f"'{field}' - collector/msazure.py reads this; update it to "
            f"match the new SDK shape (or the shape genuinely broke)."
        )


def _assert_operation(client_cls, attr_name, operations_cls, method_name):
    """Assert `client_cls.__init__` wires `attr_name` to `operations_cls`,
    and that `operations_cls` still exposes `method_name`.

    Does not instantiate `client_cls` (which would need a credential) -
    reads `__init__`'s source text instead, since operation groups are
    instance attributes rather than class attributes.
    """
    src = inspect.getsource(client_cls.__init__)
    pattern = rf"self\.{re.escape(attr_name)}\s*=\s*{re.escape(operations_cls.__name__)}\("
    assert re.search(pattern, src), (
        f"{client_cls.__module__}.{client_cls.__qualname__}.__init__ no "
        f"longer wires attribute '{attr_name}' to "
        f"{operations_cls.__name__} - collector/msazure.py calls "
        f"clients[...].{attr_name}.{method_name}(); update it to match."
    )
    assert hasattr(operations_cls, method_name), (
        f"{operations_cls.__module__}.{operations_cls.__qualname__} no "
        f"longer has method '{method_name}' - "
        f"collector/msazure.py calls it via the '{attr_name}' operation group."
    )


# --------------------------------------------------------------------------
# Negative controls - prove the assertions above can't pass vacuously.
# --------------------------------------------------------------------------


def test_negative_control_bogus_model_field_is_absent():
    pytest.importorskip("azure.mgmt.network")
    from azure.mgmt.network.models import PublicIPAddress

    inst = PublicIPAddress()
    # A real field is present ...
    assert hasattr(inst, "dns_settings")
    # ... but a made-up one is not, and _assert_fields must catch that.
    assert not hasattr(inst, "totally_bogus_field_xyz")
    with pytest.raises(AssertionError):
        _assert_fields(inst, "totally_bogus_field_xyz")


def test_negative_control_bogus_operation_wiring_is_absent():
    pytest.importorskip("azure.mgmt.network")
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.network.operations import PublicIPAddressesOperations

    # Real wiring + real method passes.
    _assert_operation(
        NetworkManagementClient, "public_ip_addresses", PublicIPAddressesOperations, "list"
    )
    # A made-up attribute name must fail.
    with pytest.raises(AssertionError):
        _assert_operation(
            NetworkManagementClient,
            "totally_bogus_attr_xyz",
            PublicIPAddressesOperations,
            "list",
        )
    # A made-up method name must fail.
    with pytest.raises(AssertionError):
        _assert_operation(
            NetworkManagementClient,
            "public_ip_addresses",
            PublicIPAddressesOperations,
            "totally_bogus_method_xyz",
        )


def test_trap_attr_to_rest_field_hides_flattened_fields():
    """Documents why `_attr_to_rest_field` must NOT be used as the field
    verification surface (see module docstring, trap #1)."""
    pytest.importorskip("azure.mgmt.network")
    from azure.mgmt.network.models import PublicIPAddress

    inst = PublicIPAddress()
    rest_fields = inst._attr_to_rest_field
    # Only the top-level ARM envelope is in this map ...
    assert "dns_settings" not in rest_fields
    # ... even though the field is genuinely present and usable.
    assert hasattr(inst, "dns_settings")


def test_trap_class_level_hasattr_misses_operation_groups():
    """Documents why client operation groups can't be checked with
    hasattr() on the class (see module docstring, trap #2)."""
    pytest.importorskip("azure.mgmt.network")
    pytest.importorskip("azure.mgmt.compute")
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import ComputeManagementClient

    assert not hasattr(NetworkManagementClient, "public_ip_addresses")
    assert not hasattr(ComputeManagementClient, "virtual_machines")


# --------------------------------------------------------------------------
# ResourceManagementClient / SubscriptionClient - subscription & RG plumbing
# --------------------------------------------------------------------------


def test_resource_management_client_contract():
    pytest.importorskip("azure.mgmt.resource")
    from azure.mgmt.resource.resources import ResourceManagementClient
    from azure.mgmt.resource.resources.operations import ResourceGroupsOperations
    from azure.mgmt.resource.resources.models import ResourceGroup

    _assert_operation(ResourceManagementClient, "resource_groups", ResourceGroupsOperations, "list")
    _assert_fields(ResourceGroup(location="eastus"), "name")


def test_subscription_client_contract():
    pytest.importorskip("azure.mgmt.subscription")
    from azure.mgmt.subscription import SubscriptionClient
    from azure.mgmt.subscription.operations import SubscriptionsOperations
    from azure.mgmt.subscription.models import Subscription

    _assert_operation(SubscriptionClient, "subscriptions", SubscriptionsOperations, "list")
    _assert_fields(Subscription(), "state", "subscription_id")


# --------------------------------------------------------------------------
# DnsManagementClient - zones / record sets (azure.dns + ALIAS/NS matching)
# --------------------------------------------------------------------------


def test_dns_management_client_contract():
    pytest.importorskip("azure.mgmt.dns")
    from azure.mgmt.dns import DnsManagementClient
    from azure.mgmt.dns.operations import ZonesOperations, RecordSetsOperations
    from azure.mgmt.dns.models import (
        Zone,
        RecordSet,
        ARecord,
        AaaaRecord,
        CnameRecord,
        NsRecord,
        SubResource,
    )

    _assert_operation(DnsManagementClient, "zones", ZonesOperations, "list_by_resource_group")
    _assert_operation(
        DnsManagementClient, "record_sets", RecordSetsOperations, "list_by_dns_zone"
    )

    _assert_fields(Zone(location="global"), "name")
    _assert_fields(
        RecordSet(),
        "fqdn",
        "a_records",
        "aaaa_records",
        "cname_record",
        "target_resource",
        "ns_records",
    )
    _assert_fields(ARecord(), "ipv4_address")
    _assert_fields(AaaaRecord(), "ipv6_address")
    _assert_fields(CnameRecord(), "cname")
    _assert_fields(NsRecord(), "nsdname")
    _assert_fields(SubResource(), "id")  # record.target_resource.id


# --------------------------------------------------------------------------
# NetworkManagementClient - public IPs, NICs, load balancers, app gateways
# --------------------------------------------------------------------------


def test_network_management_client_contract():
    pytest.importorskip("azure.mgmt.network")
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.network.operations import (
        PublicIPAddressesOperations,
        NetworkInterfacesOperations,
        LoadBalancersOperations,
        ApplicationGatewaysOperations,
    )
    from azure.mgmt.network.models import (
        PublicIPAddress,
        PublicIPAddressDnsSettings,
        NetworkInterface,
        NetworkInterfaceIPConfiguration,
        LoadBalancer,
        FrontendIPConfiguration,
        ApplicationGateway,
        ApplicationGatewayFrontendIPConfiguration,
        SubResource,
    )

    _assert_operation(
        NetworkManagementClient, "public_ip_addresses", PublicIPAddressesOperations, "list"
    )
    _assert_operation(
        NetworkManagementClient,
        "public_ip_addresses",
        PublicIPAddressesOperations,
        "list_virtual_machine_scale_set_public_ip_addresses",
    )
    _assert_operation(
        NetworkManagementClient, "network_interfaces", NetworkInterfacesOperations, "list"
    )
    _assert_operation(NetworkManagementClient, "load_balancers", LoadBalancersOperations, "list")
    _assert_operation(
        NetworkManagementClient, "application_gateways", ApplicationGatewaysOperations, "list"
    )

    _assert_fields(PublicIPAddress(), "ip_address", "dns_settings", "id")
    _assert_fields(PublicIPAddressDnsSettings(), "fqdn")  # ip.dns_settings.fqdn
    _assert_fields(NetworkInterface(), "id", "ip_configurations")
    _assert_fields(
        NetworkInterfaceIPConfiguration(), "public_ip_address"
    )  # nic.ip_configurations[].public_ip_address.id
    _assert_fields(LoadBalancer(), "frontend_ip_configurations")
    _assert_fields(
        FrontendIPConfiguration(), "public_ip_address"
    )  # lb.frontend_ip_configurations[].public_ip_address
    _assert_fields(ApplicationGateway(), "frontend_ip_configurations")
    _assert_fields(
        ApplicationGatewayFrontendIPConfiguration(), "public_ip_address"
    )  # gw.frontend_ip_configurations[].public_ip_address
    _assert_fields(SubResource(), "id")  # public_ip_address.id / nic_ref.id


# --------------------------------------------------------------------------
# CdnManagementClient - CDN endpoints, Front Door endpoints/custom domains
# --------------------------------------------------------------------------


def test_cdn_management_client_contract():
    pytest.importorskip("azure.mgmt.cdn")
    from azure.mgmt.cdn import CdnManagementClient
    from azure.mgmt.cdn.operations import (
        ProfilesOperations,
        EndpointsOperations,
        AFDEndpointsOperations,
        AFDCustomDomainsOperations,
    )
    from azure.mgmt.cdn.models import Endpoint, AFDEndpoint, AFDDomain

    _assert_operation(CdnManagementClient, "profiles", ProfilesOperations, "list_by_resource_group")
    _assert_operation(CdnManagementClient, "endpoints", EndpointsOperations, "list_by_profile")
    _assert_operation(
        CdnManagementClient, "afd_endpoints", AFDEndpointsOperations, "list_by_profile"
    )
    _assert_operation(
        CdnManagementClient, "afd_custom_domains", AFDCustomDomainsOperations, "list_by_profile"
    )

    _assert_fields(Endpoint(location="eastus"), "host_name", "id")
    _assert_fields(AFDEndpoint(location="eastus"), "host_name", "id")
    _assert_fields(AFDDomain(), "host_name")


# --------------------------------------------------------------------------
# TrafficManagerManagementClient
# --------------------------------------------------------------------------


def test_trafficmanager_client_contract():
    pytest.importorskip("azure.mgmt.trafficmanager")
    from azure.mgmt.trafficmanager import TrafficManagerManagementClient
    from azure.mgmt.trafficmanager.operations import ProfilesOperations
    from azure.mgmt.trafficmanager.models import Profile, DnsConfig

    _assert_operation(
        TrafficManagerManagementClient, "profiles", ProfilesOperations, "list_by_resource_group"
    )
    _assert_fields(Profile(), "dns_config", "id")
    _assert_fields(DnsConfig(), "fqdn")


# --------------------------------------------------------------------------
# WebSiteManagementClient - Web Apps / Static Sites
# --------------------------------------------------------------------------


def test_web_site_management_client_contract():
    pytest.importorskip("azure.mgmt.web")
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.web.operations import WebAppsOperations, StaticSitesOperations
    from azure.mgmt.web.models import Site, StaticSiteARMResource

    _assert_operation(WebSiteManagementClient, "web_apps", WebAppsOperations, "list")
    _assert_operation(WebSiteManagementClient, "static_sites", StaticSitesOperations, "list")
    _assert_fields(Site(), "host_names")
    _assert_fields(StaticSiteARMResource(), "default_hostname")


# --------------------------------------------------------------------------
# StorageManagementClient - primary/secondary endpoints
# --------------------------------------------------------------------------


def test_storage_management_client_contract():
    pytest.importorskip("azure.mgmt.storage")
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.storage.operations import StorageAccountsOperations
    from azure.mgmt.storage.models import StorageAccount, Endpoints

    _assert_operation(
        StorageManagementClient,
        "storage_accounts",
        StorageAccountsOperations,
        "list_by_resource_group",
    )
    _assert_fields(StorageAccount(), "primary_endpoints", "secondary_endpoints")
    _assert_fields(Endpoints(), "blob", "queue", "table", "file", "web", "dfs")


# --------------------------------------------------------------------------
# ApiManagementClient
# --------------------------------------------------------------------------


def test_apimanagement_client_contract():
    pytest.importorskip("azure.mgmt.apimanagement")
    from azure.mgmt.apimanagement import ApiManagementClient
    from azure.mgmt.apimanagement.operations import ApiManagementServiceOperations
    from azure.mgmt.apimanagement.models import (
        ApiManagementServiceResource,
        ApiManagementServiceSkuProperties,
    )

    _assert_operation(
        ApiManagementClient,
        "api_management_service",
        ApiManagementServiceOperations,
        "list_by_resource_group",
    )
    # ApiManagementServiceResource requires sku/location/publisher_* to
    # construct (no zero-arg form) - supply the minimal required set.
    inst = ApiManagementServiceResource(
        sku=ApiManagementServiceSkuProperties(name="Developer", capacity=1),
        location="eastus",
        publisher_email="a@example.com",
        publisher_name="x",
    )
    _assert_fields(inst, "gateway_url", "public_ip_addresses")


# --------------------------------------------------------------------------
# SqlManagementClient
# --------------------------------------------------------------------------


def test_sql_management_client_contract():
    pytest.importorskip("azure.mgmt.sql")
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.sql.operations import ServersOperations
    from azure.mgmt.sql.models import Server

    _assert_operation(SqlManagementClient, "servers", ServersOperations, "list_by_resource_group")
    _assert_fields(Server(), "fully_qualified_domain_name")


# --------------------------------------------------------------------------
# ContainerRegistryManagementClient
# --------------------------------------------------------------------------


def test_containerregistry_client_contract():
    pytest.importorskip("azure.mgmt.containerregistry")
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    from azure.mgmt.containerregistry.operations import RegistriesOperations
    from azure.mgmt.containerregistry.models import Registry

    _assert_operation(
        ContainerRegistryManagementClient,
        "registries",
        RegistriesOperations,
        "list_by_resource_group",
    )
    _assert_fields(Registry(location="eastus", sku=None), "login_server")


# --------------------------------------------------------------------------
# ContainerInstanceManagementClient
# --------------------------------------------------------------------------


def test_containerinstance_client_contract():
    pytest.importorskip("azure.mgmt.containerinstance")
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    from azure.mgmt.containerinstance.operations import ContainerGroupsOperations
    from azure.mgmt.containerinstance.models import ContainerGroup, IpAddress

    _assert_operation(
        ContainerInstanceManagementClient,
        "container_groups",
        ContainerGroupsOperations,
        "list_by_resource_group",
    )
    _assert_fields(
        ContainerGroup(containers=[], os_type="Linux"), "ip_address"
    )  # container.ip_address.ip
    _assert_fields(IpAddress(ports=[], type="Public"), "ip")


# --------------------------------------------------------------------------
# SearchManagementClient (Cognitive Search)
# --------------------------------------------------------------------------


def test_cognitivesearch_client_contract():
    pytest.importorskip("azure.mgmt.search")
    from azure.mgmt.search import SearchManagementClient
    from azure.mgmt.search.operations import ServicesOperations
    from azure.mgmt.search.models import SearchService

    _assert_operation(
        SearchManagementClient, "services", ServicesOperations, "list_by_resource_group"
    )
    _assert_fields(SearchService(location="eastus"), "name")


# --------------------------------------------------------------------------
# RedisManagementClient
# --------------------------------------------------------------------------


def test_redis_client_contract():
    pytest.importorskip("azure.mgmt.redis")
    from azure.mgmt.redis import RedisManagementClient
    from azure.mgmt.redis.operations import RedisOperations
    from azure.mgmt.redis.models import RedisResource

    _assert_operation(RedisManagementClient, "redis", RedisOperations, "list_by_resource_group")
    _assert_fields(RedisResource(location="eastus", sku=None), "host_name")


# --------------------------------------------------------------------------
# ComputeManagementClient - VM / VMSS
# --------------------------------------------------------------------------


def test_compute_client_contract():
    pytest.importorskip("azure.mgmt.compute")
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.operations import (
        VirtualMachinesOperations,
        VirtualMachineScaleSetsOperations,
    )
    from azure.mgmt.compute.models import (
        VirtualMachine,
        NetworkProfile,
        NetworkInterfaceReference,
        VirtualMachineScaleSet,
    )

    _assert_operation(
        ComputeManagementClient, "virtual_machines", VirtualMachinesOperations, "list"
    )
    _assert_operation(
        ComputeManagementClient,
        "virtual_machine_scale_sets",
        VirtualMachineScaleSetsOperations,
        "list",
    )

    _assert_fields(VirtualMachine(location="eastus"), "network_profile")
    _assert_fields(NetworkProfile(), "network_interfaces")
    _assert_fields(NetworkInterfaceReference(), "id")  # nic_ref.id
    _assert_fields(VirtualMachineScaleSet(location="eastus"), "name")

    # Also used off the network client for VMSS public IPs - covered again
    # here since _collect_vm_data depends on it directly.
    pytest.importorskip("azure.mgmt.network")
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.network.operations import PublicIPAddressesOperations

    _assert_operation(
        NetworkManagementClient,
        "public_ip_addresses",
        PublicIPAddressesOperations,
        "list_virtual_machine_scale_set_public_ip_addresses",
    )


# --------------------------------------------------------------------------
# ContainerServiceClient (AKS)
# --------------------------------------------------------------------------


def test_aks_client_contract():
    pytest.importorskip("azure.mgmt.containerservice")
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.containerservice.operations import ManagedClustersOperations
    from azure.mgmt.containerservice.models import ManagedCluster

    _assert_operation(
        ContainerServiceClient,
        "managed_clusters",
        ManagedClustersOperations,
        "list_by_resource_group",
    )
    _assert_fields(ManagedCluster(location="eastus"), "fqdn", "private_fqdn")


# --------------------------------------------------------------------------
# ContainerAppsAPIClient
# --------------------------------------------------------------------------


def test_containerapps_client_contract():
    pytest.importorskip("azure.mgmt.appcontainers")
    from azure.mgmt.appcontainers import ContainerAppsAPIClient
    from azure.mgmt.appcontainers.operations import ContainerAppsOperations
    from azure.mgmt.appcontainers.models import ContainerApp, Configuration, Ingress

    _assert_operation(
        ContainerAppsAPIClient,
        "container_apps",
        ContainerAppsOperations,
        "list_by_resource_group",
    )
    _assert_fields(
        ContainerApp(location="eastus"), "configuration", "latest_revision_fqdn"
    )
    _assert_fields(Configuration(), "ingress")  # app.configuration.ingress.fqdn
    _assert_fields(Ingress(), "fqdn")


# --------------------------------------------------------------------------
# CosmosDBManagementClient
# --------------------------------------------------------------------------


def test_cosmosdb_client_contract():
    pytest.importorskip("azure.mgmt.cosmosdb")
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    from azure.mgmt.cosmosdb.operations import DatabaseAccountsOperations
    from azure.mgmt.cosmosdb.models import DatabaseAccountGetResults

    _assert_operation(
        CosmosDBManagementClient,
        "database_accounts",
        DatabaseAccountsOperations,
        "list_by_resource_group",
    )
    _assert_fields(DatabaseAccountGetResults(location="eastus"), "document_endpoint")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
