#!/usr/bin/env python3
"""Contract tests pinning the GCP SDK shapes collector/gcp.py depends on.

The point of this file: a dependabot bump of any google-cloud-* package that
renames/removes a field or method the collector reads should fail CI here,
loudly, instead of silently breaking detection (the field read just returns
None/AttributeError and that resource type quietly stops being collected).

No network calls and no GCP credentials are used anywhere in this file:
proto-plus/protobuf message classes are introspected directly (no instance
needed), and the couple of non-proto google-cloud-dns / google-cloud-storage
classes that only expose their attributes on *instances* are constructed
locally with client=None (pure object construction, no I/O). The one place
that needs to exercise real collector logic (Cloud SQL response parsing) runs
the actual collector function with every other GCP client class short-circuited
to raise Forbidden immediately, and google.auth.transport.requests.AuthorizedSession
replaced with a fake session — nothing hits the network there either.

Run: python3 -m pytest tests/test_contract_gcp.py -v
"""

import os
import sys

# Make the repo root importable regardless of where the test is run from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# --- Guard every optional GCP SDK collector/gcp.py imports. CI (pip install .)
# installs all of them; a dev machine without one shouldn't see spurious
# failures for SDKs it never touches. ---
pytest.importorskip("google.auth")
pytest.importorskip("google.api_core")
gcp_dns = pytest.importorskip("google.cloud.dns")
gcp_storage = pytest.importorskip("google.cloud.storage")
compute_v1 = pytest.importorskip("google.cloud.compute_v1")
functions_v2 = pytest.importorskip("google.cloud.functions_v2")
run_v2 = pytest.importorskip("google.cloud.run_v2")
appengine_admin_v1 = pytest.importorskip("google.cloud.appengine_admin_v1")
container_v1 = pytest.importorskip("google.cloud.container_v1")
artifactregistry_v1 = pytest.importorskip("google.cloud.artifactregistry_v1")
resourcemanager_v3 = pytest.importorskip("google.cloud.resourcemanager_v3")
locations_pb2 = pytest.importorskip("google.cloud.location.locations_pb2")
pytest.importorskip("requests")

from google.api_core.exceptions import Forbidden  # noqa: E402

# The collector module itself pulls in all of the above at import time, so
# guard it too (belt and suspenders if any transitive import is missing).
collector_gcp = pytest.importorskip("collector.gcp")


# ---------------------------------------------------------------------------
# Local helpers. The whole point of this file is a clear failure message
# naming the message class and the missing field/method, so a dependabot PR
# fails with something a human can act on instead of a bare AssertionError.
# ---------------------------------------------------------------------------

def _assert_proto_plus_field(message_cls, field_name):
    """Assert `field_name` is a declared field on a proto-plus message class."""
    fields = getattr(getattr(message_cls, "meta", None), "fields", None)
    assert fields is not None, (
        f"{message_cls.__module__}.{message_cls.__qualname__} has no "
        f"proto-plus 'meta.fields' - is this still a proto-plus message class?"
    )
    assert field_name in fields, (
        f"GCP SDK contract broken: {message_cls.__module__}.{message_cls.__qualname__} "
        f"no longer has field '{field_name}'. collector/gcp.py reads this field "
        f"directly and will silently get None/AttributeError instead."
    )


def _assert_raw_protobuf_field(message_cls, field_name):
    """Assert `field_name` is declared on a plain (non proto-plus) protobuf message."""
    fields_by_name = message_cls.DESCRIPTOR.fields_by_name
    assert field_name in fields_by_name, (
        f"GCP SDK contract broken: {message_cls.__module__}.{message_cls.__qualname__} "
        f"no longer has field '{field_name}'. collector/gcp.py reads this field "
        f"directly and will silently get None/AttributeError instead."
    )


def _assert_instance_attr(instance, attr_name, cls_label):
    """Assert `attr_name` exists on a constructed instance (for classes whose
    attributes are set in __init__ rather than declared as class descriptors,
    so introspecting the class itself would report False negatives)."""
    assert hasattr(instance, attr_name), (
        f"GCP SDK contract broken: {cls_label} no longer exposes attribute "
        f"'{attr_name}'. collector/gcp.py reads this field directly and will "
        f"silently get None/AttributeError instead."
    )


def _assert_client_method(cls, method_name):
    """Assert a client class still exposes the method collector/gcp.py calls."""
    assert hasattr(cls, method_name), (
        f"GCP SDK contract broken: {cls.__module__}.{cls.__qualname__} no "
        f"longer has method '{method_name}'. collector/gcp.py calls this "
        f"directly and would raise AttributeError."
    )


# ---------------------------------------------------------------------------
# Negative control - proves the helpers actually detect a missing field/method,
# so this test file can't be passing vacuously.
# ---------------------------------------------------------------------------

def test_negative_control_bogus_field_and_method_are_absent():
    with pytest.raises(AssertionError, match="no longer has field"):
        _assert_proto_plus_field(run_v2.Service, "this_field_definitely_does_not_exist")

    with pytest.raises(AssertionError, match="no longer has field"):
        _assert_raw_protobuf_field(locations_pb2.Location, "this_field_definitely_does_not_exist")

    with pytest.raises(AssertionError, match="no longer has method"):
        _assert_client_method(run_v2.ServicesClient, "this_method_definitely_does_not_exist")

    class _Empty:
        pass

    with pytest.raises(AssertionError, match="no longer exposes attribute"):
        _assert_instance_attr(_Empty(), "this_attr_definitely_does_not_exist", "_Empty")


# ---------------------------------------------------------------------------
# Cloud DNS - zones and record sets (collector/gcp.py: _dns_for_project,
# and the dnszone rows in _infra_for_project)
# ---------------------------------------------------------------------------

def test_cloud_dns_client_and_zone_shapes():
    _assert_client_method(gcp_dns.client.Client, "list_zones")
    _assert_client_method(gcp_dns.zone.ManagedZone, "list_resource_record_sets")

    # ManagedZone.name / .dns_name and ResourceRecordSet.record_type / .name /
    # .rrdatas are plain instance attributes (not class-level descriptors), so
    # they must be checked on a constructed instance. Construction here is
    # pure object creation - client=None, no I/O.
    managed_zone = gcp_dns.zone.ManagedZone(name="myzone", dns_name="example.com.", client=None)
    _assert_instance_attr(managed_zone, "name", "google.cloud.dns.zone.ManagedZone")
    _assert_instance_attr(managed_zone, "dns_name", "google.cloud.dns.zone.ManagedZone")

    record_set = gcp_dns.resource_record_set.ResourceRecordSet(
        name="a.example.com.", record_type="A", ttl=300, rrdatas=["203.0.113.10"], zone=None
    )
    _assert_instance_attr(record_set, "record_type", "google.cloud.dns.resource_record_set.ResourceRecordSet")
    _assert_instance_attr(record_set, "name", "google.cloud.dns.resource_record_set.ResourceRecordSet")
    _assert_instance_attr(record_set, "rrdatas", "google.cloud.dns.resource_record_set.ResourceRecordSet")


# ---------------------------------------------------------------------------
# Cloud Storage buckets
# ---------------------------------------------------------------------------

def test_storage_bucket_shape():
    _assert_client_method(gcp_storage.Client, "list_buckets")

    # Bucket.name is a plain instance attribute (set in __init__), not a
    # class-level descriptor.
    bucket = gcp_storage.Bucket(client=None, name="mybucket")
    _assert_instance_attr(bucket, "name", "google.cloud.storage.bucket.Bucket")


# ---------------------------------------------------------------------------
# Compute: ForwardingRule.I_p_address (note: proto-plus mangles the "IP"
# acronym as "I_p", NOT "IP_address" - this is the exact attribute
# collector/gcp.py reads at gcp.py's `rule.I_p_address`)
# ---------------------------------------------------------------------------

def test_forwarding_rule_ip_address_shape():
    _assert_client_method(compute_v1.ForwardingRulesClient, "aggregated_list")
    _assert_proto_plus_field(compute_v1.ForwardingRulesScopedList, "forwarding_rules")
    _assert_proto_plus_field(compute_v1.ForwardingRule, "I_p_address")


# ---------------------------------------------------------------------------
# Compute: Instance.network_interfaces[].access_configs[].nat_i_p
# ---------------------------------------------------------------------------

def test_compute_instance_public_ip_shape():
    _assert_client_method(compute_v1.InstancesClient, "aggregated_list")
    _assert_proto_plus_field(compute_v1.InstancesScopedList, "instances")
    _assert_proto_plus_field(compute_v1.Instance, "network_interfaces")
    _assert_proto_plus_field(compute_v1.NetworkInterface, "access_configs")
    _assert_proto_plus_field(compute_v1.AccessConfig, "nat_i_p")


# ---------------------------------------------------------------------------
# Cloud Functions v2: service_config.uri
# ---------------------------------------------------------------------------

def test_cloud_functions_service_config_uri_shape():
    _assert_client_method(functions_v2.FunctionServiceClient, "list_functions")
    _assert_proto_plus_field(functions_v2.Function, "service_config")
    _assert_proto_plus_field(functions_v2.ServiceConfig, "uri")


# ---------------------------------------------------------------------------
# Cloud Run: run_v2.Service.uri
# ---------------------------------------------------------------------------

def test_cloud_run_service_uri_shape():
    _assert_client_method(run_v2.ServicesClient, "list_services")
    _assert_proto_plus_field(run_v2.Service, "uri")


def test_cloud_run_has_no_location_wildcard_or_list_locations():
    """Pin the assumption collector/gcp.py's _CLOUD_RUN_REGIONS comment makes:
    the Cloud Run Admin API v2 client has no list_locations() to discover
    regions dynamically. If the SDK ever adds one, the hardcoded region list
    in collector/gcp.py becomes an avoidable staleness risk (new regions
    silently missed) and should be revisited - this test will start failing
    to flag that, rather than silently going stale.
    """
    assert not hasattr(run_v2.ServicesClient, "list_locations"), (
        "run_v2.ServicesClient now has list_locations() - the hardcoded "
        "_CLOUD_RUN_REGIONS tuple in collector/gcp.py can (and should) be "
        "replaced with a dynamic region lookup instead of a maintained list "
        "that silently misses new regions."
    )


# ---------------------------------------------------------------------------
# App Engine: Application.default_hostname
# ---------------------------------------------------------------------------

def test_app_engine_default_hostname_shape():
    _assert_client_method(appengine_admin_v1.ApplicationsClient, "get_application")
    _assert_proto_plus_field(appengine_admin_v1.Application, "default_hostname")


# ---------------------------------------------------------------------------
# GKE: container_v1.Cluster.endpoint
# ---------------------------------------------------------------------------

def test_gke_cluster_endpoint_shape():
    _assert_client_method(container_v1.ClusterManagerClient, "list_clusters")
    _assert_proto_plus_field(container_v1.ListClustersResponse, "clusters")
    _assert_proto_plus_field(container_v1.Cluster, "endpoint")


# ---------------------------------------------------------------------------
# Artifact Registry: Repository.registry_uri, plus the list_locations() /
# Location.location_id path used to enumerate real locations (this list_locations
# comes from the shared google.cloud.location package, a plain protobuf message,
# not a proto-plus one - hence the separate raw-protobuf helper).
# ---------------------------------------------------------------------------

def test_artifact_registry_repository_uri_shape():
    _assert_client_method(artifactregistry_v1.ArtifactRegistryClient, "list_locations")
    _assert_client_method(artifactregistry_v1.ArtifactRegistryClient, "list_repositories")
    _assert_raw_protobuf_field(locations_pb2.ListLocationsResponse, "locations")
    _assert_raw_protobuf_field(locations_pb2.Location, "location_id")
    _assert_proto_plus_field(artifactregistry_v1.Repository, "registry_uri")


# ---------------------------------------------------------------------------
# Cloud SQL - no stable google-cloud-* client exists for SQL Admin, so
# collector/gcp.py calls the REST API directly via AuthorizedSession. There is
# no SDK model to introspect here; instead we pin *our own* parsing by
# running the real collector function with every other GCP client
# short-circuited, and AuthorizedSession replaced with a fake in-memory
# session. This exercises the actual ipAddresses/type/ipAddress filtering
# logic in collector/gcp.py._infra_for_project, not a reimplementation of it.
# ---------------------------------------------------------------------------

def _raise_forbidden(*_args, **_kwargs):
    raise Forbidden("mocked short-circuit for test - not a real API response")


# (module_or_class, attribute_name) pairs for every GCP client
# collector/gcp.py._infra_for_project constructs *before* the Cloud SQL block.
# Short-circuiting all of them to raise Forbidden immediately means the real
# function runs end-to-end with no network calls and no real credentials,
# and reaches the Cloud SQL block exercising the genuine parsing logic.
_INFRA_CLIENT_SHORT_CIRCUIT_TARGETS = (
    (collector_gcp.dns.client, "Client"),
    (collector_gcp.storage, "Client"),
    (collector_gcp.compute_v1, "ForwardingRulesClient"),
    (collector_gcp.functions_v2, "FunctionServiceClient"),
    (collector_gcp.compute_v1, "InstancesClient"),
    (collector_gcp.run_v2, "ServicesClient"),
    (collector_gcp.appengine_admin_v1, "ApplicationsClient"),
    (collector_gcp.container_v1, "ClusterManagerClient"),
    (collector_gcp.artifactregistry_v1, "ArtifactRegistryClient"),
)


class _FakeSQLResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.content = b"{}"

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


class _FakeSQLSession:
    """Stands in for google.auth.transport.requests.AuthorizedSession. Records
    the requested URL so the test can also pin the REST path shape, and hands
    back one page of a realistic SQL Admin instances.list response - no
    network I/O involved."""

    def __init__(self, project, payload):
        self._project = project
        self._payload = payload
        self.requested_urls = []

    def get(self, url, params=None):
        self.requested_urls.append(url)
        return _FakeSQLResponse(self._payload)


def test_cloudsql_rest_path_and_primary_ip_filtering(monkeypatch):
    proj = "test-project-123"

    for target, attr in _INFRA_CLIENT_SHORT_CIRCUIT_TARGETS:
        monkeypatch.setattr(target, attr, _raise_forbidden)

    payload = {
        "items": [
            {
                "ipAddresses": [
                    {"type": "PRIMARY", "ipAddress": "203.0.113.5"},
                    {"type": "PRIVATE", "ipAddress": "10.0.0.5"},
                    {"type": "OUTGOING", "ipAddress": "203.0.113.9"},
                ]
            }
        ]
    }
    fake_session = _FakeSQLSession(proj, payload)
    monkeypatch.setattr(collector_gcp, "AuthorizedSession", lambda credentials: fake_session)

    rows = collector_gcp._infra_for_project(proj, credentials=object())

    # Pin the REST path shape: host + exact SQL Admin v1beta4 instances path.
    assert fake_session.requested_urls, "Cloud SQL block never called AuthorizedSession.get()"
    called_url = fake_session.requested_urls[0]
    assert called_url == (
        f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{proj}/instances"
    ), (
        "collector/gcp.py's Cloud SQL REST path changed shape: "
        f"expected the v1beta4 projects/{{project}}/instances path, got {called_url!r}"
    )

    # Pin the parsing/normalization contract: only PRIMARY public IPs are
    # emitted, as bare string values (not dicts), and PRIVATE/OUTGOING are
    # dropped.
    cloudsql_rows = [row for row in rows if row[1] == "cloudsql"]
    assert cloudsql_rows == [[proj, "cloudsql", "203.0.113.5"]], (
        f"Cloud SQL IP filtering contract broken: expected only the PRIMARY "
        f"public IP as a bare value, got {cloudsql_rows!r}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
