#!/usr/bin/env python3
"""Contract tests pinning the OCI SDK shapes collector/oracle.py depends on.

The multi-region/multi-service scan in collector/oracle.py was written without
live API access, so a dependabot bump to the `oci` package that silently
renames or removes a client method or response field should fail CI here
instead of quietly breaking takeover detection in production.

No network calls and no OCI credentials are used anywhere in this file.
`oci.config.from_file()` is deliberately never called (it reads ~/.oci/config
and would pick up real config, or fail outright with no config present) -
everything here is class/instance introspection only.

## The trap this file deliberately avoids

OCI model classes declare their field map (`swagger_types`) as an *instance*
attribute, assigned inside `__init__` - not as a class attribute. So
`SomeModel.swagger_types` raises `AttributeError` even on a perfectly healthy
SDK (confirmed against the installed oci==2.182.0). Every OCI model used here
takes only optional keyword arguments, so instantiating with no arguments
(`SomeModel()`) is always safe (no network I/O - it just populates attributes)
and is what actually exposes `swagger_types`. See
test_trap_class_level_swagger_types_is_absent below.

Client operation methods (e.g. `oci.dns.DnsClient.list_zones`), by contrast,
*are* declared at class level by the SDK's codegen, so `hasattr()` on the
class itself (no instantiation, no config, no credentials) is the correct and
sufficient check for those.

Run: python3 -m pytest tests/test_contract_oracle.py -v
"""

import pytest


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _assert_client_method(client_cls, method_name):
    """Assert `client_cls` still declares `method_name` at class level.

    Failure names the client class and the missing method so a
    dependabot-bump breakage points straight at collector/oracle.py's usage.
    """
    assert hasattr(client_cls, method_name), (
        f"{client_cls.__module__}.{client_cls.__qualname__} no longer has "
        f"method '{method_name}' - collector/oracle.py calls this; update "
        f"it to match the new SDK shape (or the shape genuinely broke)."
    )


def _assert_swagger_field(model_cls, field):
    """Assert `field` is declared in `model_cls().swagger_types`.

    Instantiates `model_cls` with no arguments to reach the instance-level
    `swagger_types` map (see module docstring) - this does not perform any
    network I/O. Failure names the model class and the missing field so a
    dependabot-bump breakage points straight at collector/oracle.py's usage.
    """
    instance = model_cls()
    assert field in instance.swagger_types, (
        f"{model_cls.__module__}.{model_cls.__qualname__} no longer has "
        f"field '{field}' - collector/oracle.py reads this; update it to "
        f"match the new SDK shape (or the shape genuinely broke)."
    )


# --------------------------------------------------------------------------
# Negative controls - prove the assertions above can't pass vacuously.
# --------------------------------------------------------------------------


def test_negative_control_bogus_client_method_is_absent():
    pytest.importorskip("oci")
    import oci

    # A real method is present ...
    assert hasattr(oci.dns.DnsClient, "list_zones")
    # ... but a made-up one is not, and _assert_client_method must catch that.
    assert not hasattr(oci.dns.DnsClient, "totally_bogus_method_xyz")
    with pytest.raises(AssertionError, match="no longer has"):
        _assert_client_method(oci.dns.DnsClient, "totally_bogus_method_xyz")


def test_negative_control_bogus_swagger_field_is_absent():
    pytest.importorskip("oci")
    import oci

    inst = oci.dns.models.ZoneSummary()
    # A real field is present ...
    assert "name" in inst.swagger_types
    # ... but a made-up one is not, and _assert_swagger_field must catch that.
    assert "totally_bogus_field_xyz" not in inst.swagger_types
    with pytest.raises(AssertionError, match="no longer has"):
        _assert_swagger_field(oci.dns.models.ZoneSummary, "totally_bogus_field_xyz")


def test_trap_class_level_swagger_types_is_absent():
    """Documents why `swagger_types` must be read off an *instance*, not the
    class (see module docstring)."""
    pytest.importorskip("oci")
    import oci

    assert not hasattr(oci.dns.models.ZoneSummary, "swagger_types")
    assert not hasattr(oci.database.models.AutonomousDatabaseSummary, "swagger_types")
    # ... yet a zero-arg instance exposes it without any network I/O.
    assert hasattr(oci.dns.models.ZoneSummary(), "swagger_types")


# --------------------------------------------------------------------------
# Config / pagination / error plumbing shared by dns() and infra()
# --------------------------------------------------------------------------


def test_config_pagination_and_error_plumbing_contract():
    pytest.importorskip("oci")
    import oci

    assert hasattr(oci.config, "from_file")  # _load_config() - never called here
    assert hasattr(oci.pagination, "list_call_get_all_results")

    # oci.response.Response.next_page drives _zone_records()'s pagination
    # loop; constructing a Response does no I/O.
    resp = oci.response.Response(status=200, headers={}, data=None, request=None)
    assert hasattr(resp, "next_page")

    # ServiceError.status / .code are read in every _try()/except block.
    # Constructing one directly (not raising it) does no I/O.
    err = oci.exceptions.ServiceError(
        status=404,
        code="NotAuthorizedOrNotFound",
        headers={},
        message="x",
    )
    assert hasattr(err, "status")
    assert hasattr(err, "code")


# --------------------------------------------------------------------------
# IdentityClient - compartments, region subscriptions, availability domains
# --------------------------------------------------------------------------


def test_identity_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.identity.IdentityClient, "list_compartments")
    _assert_client_method(oci.identity.IdentityClient, "list_region_subscriptions")
    _assert_client_method(oci.identity.IdentityClient, "list_availability_domains")

    _assert_swagger_field(oci.identity.models.Compartment, "id")  # c.id
    _assert_swagger_field(oci.identity.models.RegionSubscription, "region_name")
    _assert_swagger_field(oci.identity.models.RegionSubscription, "status")
    _assert_swagger_field(oci.identity.models.AvailabilityDomain, "name")  # ad.name


# --------------------------------------------------------------------------
# DnsClient - zones / zone records (NS/A/AAAA/CNAME matching)
# --------------------------------------------------------------------------


def test_dns_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.dns.DnsClient, "list_zones")
    _assert_client_method(oci.dns.DnsClient, "get_zone_records")

    _assert_swagger_field(oci.dns.models.ZoneSummary, "id")
    _assert_swagger_field(oci.dns.models.ZoneSummary, "name")
    _assert_swagger_field(oci.dns.models.RecordCollection, "items")  # resp.data.items
    _assert_swagger_field(oci.dns.models.Record, "rtype")
    _assert_swagger_field(oci.dns.models.Record, "domain")
    _assert_swagger_field(oci.dns.models.Record, "rdata")


# --------------------------------------------------------------------------
# VirtualNetworkClient - public IPs, VNIC public IP lookup
# --------------------------------------------------------------------------


def test_virtual_network_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.core.VirtualNetworkClient, "list_public_ips")
    _assert_client_method(oci.core.VirtualNetworkClient, "get_vnic")

    _assert_swagger_field(oci.core.models.PublicIp, "ip_address")
    _assert_swagger_field(oci.core.models.Vnic, "public_ip")


# --------------------------------------------------------------------------
# LoadBalancerClient / NetworkLoadBalancerClient
# --------------------------------------------------------------------------


def test_load_balancer_clients_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.load_balancer.LoadBalancerClient, "list_load_balancers")
    _assert_client_method(
        oci.network_load_balancer.NetworkLoadBalancerClient, "list_network_load_balancers"
    )

    _assert_swagger_field(oci.load_balancer.models.LoadBalancer, "ip_addresses")
    _assert_swagger_field(oci.load_balancer.models.IpAddress, "ip_address")

    _assert_swagger_field(
        oci.network_load_balancer.models.NetworkLoadBalancerSummary, "is_private"
    )
    _assert_swagger_field(
        oci.network_load_balancer.models.NetworkLoadBalancerSummary, "ip_addresses"
    )
    _assert_swagger_field(oci.network_load_balancer.models.IpAddress, "is_public")
    _assert_swagger_field(oci.network_load_balancer.models.IpAddress, "ip_address")


# --------------------------------------------------------------------------
# ObjectStorageClient - namespace + buckets
# --------------------------------------------------------------------------


def test_object_storage_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.object_storage.ObjectStorageClient, "get_namespace")
    _assert_client_method(oci.object_storage.ObjectStorageClient, "list_buckets")

    _assert_swagger_field(oci.object_storage.models.BucketSummary, "name")


# --------------------------------------------------------------------------
# DatabaseClient - Autonomous Database + DB Systems
# --------------------------------------------------------------------------


def test_database_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.database.DatabaseClient, "list_autonomous_databases")
    _assert_client_method(oci.database.DatabaseClient, "list_db_systems")

    _assert_swagger_field(oci.database.models.AutonomousDatabaseSummary, "public_endpoint")
    _assert_swagger_field(oci.database.models.AutonomousDatabaseSummary, "connection_urls")
    _assert_swagger_field(
        oci.database.models.AutonomousDatabaseConnectionUrls, "sql_dev_web_url"
    )

    _assert_swagger_field(oci.database.models.DbSystemSummary, "scan_dns_name")
    _assert_swagger_field(oci.database.models.DbSystemSummary, "hostname")
    _assert_swagger_field(oci.database.models.DbSystemSummary, "domain")


# --------------------------------------------------------------------------
# GatewayClient (API Gateway)
# --------------------------------------------------------------------------


def test_api_gateway_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.apigateway.GatewayClient, "list_gateways")

    _assert_swagger_field(oci.apigateway.models.GatewaySummary, "hostname")
    _assert_swagger_field(oci.apigateway.models.GatewaySummary, "endpoint_type")


# --------------------------------------------------------------------------
# FunctionsManagementClient
# --------------------------------------------------------------------------


def test_functions_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(oci.functions.FunctionsManagementClient, "list_applications")
    _assert_client_method(oci.functions.FunctionsManagementClient, "list_functions")

    _assert_swagger_field(oci.functions.models.ApplicationSummary, "id")  # app.id
    _assert_swagger_field(oci.functions.models.FunctionSummary, "invoke_endpoint")


# --------------------------------------------------------------------------
# ContainerInstanceClient
# --------------------------------------------------------------------------


def test_container_instance_client_contract():
    pytest.importorskip("oci")
    import oci

    _assert_client_method(
        oci.container_instances.ContainerInstanceClient, "list_container_instances"
    )
    _assert_client_method(
        oci.container_instances.ContainerInstanceClient, "get_container_instance"
    )

    _assert_swagger_field(oci.container_instances.models.ContainerInstanceSummary, "id")
    _assert_swagger_field(oci.container_instances.models.ContainerInstance, "vnics")
    _assert_swagger_field(oci.container_instances.models.ContainerVnic, "vnic_id")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
