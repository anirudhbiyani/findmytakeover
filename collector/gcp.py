#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor

import requests
import google.auth
from google.api_core.exceptions import Forbidden, GoogleAPICallError, NotFound
from google.auth.transport.requests import AuthorizedSession
from google.cloud import dns
from google.cloud import resourcemanager_v3
from google.oauth2 import service_account
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import functions_v2
from google.cloud import run_v2
from google.cloud import appengine_admin_v1
from google.cloud import container_v1
from google.cloud import artifactregistry_v1
import click

from collector import is_cloud_nameserver, zone_key, MAX_WORKERS

# Record types we're interested in for DNS
_A_AAAA_TYPES = frozenset(("A", "AAAA"))
_CNAME_TYPE = "CNAME"

_USE_CLI_CREDS = "default"

# Cloud Run's Admin API v2 requires a concrete region per ListServicesRequest —
# it has no location wildcard ("-") and no list_locations() method (unlike
# Cloud Functions / GKE / Artifact Registry). We fan out over the known set of
# regions Cloud Run is available in; add new regions here as Google ships them.
_CLOUD_RUN_REGIONS = (
    "africa-south1",
    "asia-east1", "asia-east2",
    "asia-northeast1", "asia-northeast2", "asia-northeast3",
    "asia-south1", "asia-south2",
    "asia-southeast1", "asia-southeast2",
    "australia-southeast1", "australia-southeast2",
    "europe-central2",
    "europe-north1", "europe-north2",
    "europe-southwest1",
    "europe-west1", "europe-west2", "europe-west3", "europe-west4",
    "europe-west6", "europe-west8", "europe-west9", "europe-west10", "europe-west12",
    "me-central1", "me-central2", "me-west1",
    "northamerica-northeast1", "northamerica-northeast2",
    "southamerica-east1", "southamerica-west1",
    "us-central1",
    "us-east1", "us-east4", "us-east5",
    "us-south1",
    "us-west1", "us-west2", "us-west3", "us-west4",
)


def _is_default_credentials(path):
    return str(path).strip().lower() == _USE_CLI_CREDS


def _api_disabled(exc):
    """A Forbidden that just means the project doesn't use this API — expected, not worth reporting."""
    msg = str(getattr(exc, "message", exc))
    return "has not been used" in msg or "it is disabled" in msg


def _load_credentials(path):
    """Return GCP credentials from a service account file or Application Default Credentials."""
    if _is_default_credentials(path):
        credentials, _ = google.auth.default()
        return credentials
    return service_account.Credentials.from_service_account_file(path)


def _resolve_projects(projects, credentials, use_default):
    """Return the project list, auto-discovering from Resource Manager when using default credentials."""
    if not use_default:
        return projects

    if projects:
        return projects

    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    discovered = []
    for project in client.search_projects(query="state:ACTIVE"):
        discovered.append(project.project_id)

    click.echo(f"Auto-discovered {len(discovered)} GCP project(s) from CLI credentials")
    return discovered


class gcp:
    @staticmethod
    def dns(projects, path):
        """Collect DNS records from GCP projects."""
        credentials = _load_credentials(path)
        projects = _resolve_projects(projects, credentials, _is_default_credentials(path))

        dnsdata = []
        # Projects are independent and I/O-bound — collect them concurrently.
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for rows in pool.map(lambda p: _dns_for_project(p, credentials), projects):
                dnsdata.extend(rows)
        return dnsdata

    @staticmethod
    def infra(projects, path):
        """Collect infrastructure data from GCP projects."""
        credentials = _load_credentials(path)
        projects = _resolve_projects(projects, credentials, _is_default_credentials(path))

        infradata = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for rows in pool.map(lambda p: _infra_for_project(p, credentials), projects):
                infradata.extend(rows)
        return infradata


def _dns_for_project(proj, credentials):
    """Collect Cloud DNS records for a single project (returns rows)."""
    click.echo(f"Reading DNS data from Google Cloud Project - {proj}")
    dnsdata = []
    try:
        dns_client = dns.client.Client(credentials=credentials, project=proj)

        for managed_zone in dns_client.list_zones():
            dns_record_client = dns.zone.ManagedZone(
                name=managed_zone.name, client=dns_client
            )

            for record_set in dns_record_client.list_resource_record_sets():
                record_type = record_set.record_type
                record_name = record_set.name.rstrip(".")

                if record_type in _A_AAAA_TYPES:
                    dnsdata.extend(
                        [proj, record_name, ip] for ip in record_set.rrdatas
                    )
                elif record_type == _CNAME_TYPE:
                    dnsdata.extend(
                        [proj, record_name, cname.rstrip(".")]
                        for cname in record_set.rrdatas
                    )
                elif record_type == "NS" and zone_key(record_name) != zone_key(
                    managed_zone.dns_name
                ):
                    # Child delegation to a cloud NS pool → dangling if the
                    # delegated zone is not in the inventory (see infra()).
                    if any(is_cloud_nameserver(ns) for ns in record_set.rrdatas):
                        dnsdata.append([proj, record_name, zone_key(record_name)])
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping DNS collection for project {proj} - access denied")

    return dnsdata


def _infra_for_project(proj, credentials):
    """Collect infrastructure endpoints for a single project (returns rows)."""
    click.echo(f"Getting Infrastructure details from Google Cloud Project - {proj}")
    infradata = []

    # DNS zone names — the "live zones" a delegated NS record is matched against.
    try:
        dns_client = dns.client.Client(credentials=credentials, project=proj)
        for managed_zone in dns_client.list_zones():
            infradata.append([proj, "dnszone", zone_key(managed_zone.dns_name)])
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping DNS zones for project {proj} - access denied")

    # Cloud Storage Buckets
    try:
        storage_client = storage.Client(credentials=credentials, project=proj)
        infradata.extend(
            [proj, "bucket", bucket.name]
            for bucket in storage_client.list_buckets()
        )
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping Storage for project {proj} - access denied")

    # LoadBalancer IP Addresses
    try:
        forwarding_rules_client = compute_v1.ForwardingRulesClient(credentials=credentials)
        for _, response in forwarding_rules_client.aggregated_list(project=proj):
            if response.forwarding_rules:
                infradata.extend(
                    [proj, "loadbalancer", rule.I_p_address]
                    for rule in response.forwarding_rules
                )
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping Forwarding Rules for project {proj} - access denied")

    # Cloud Functions
    try:
        function_client = functions_v2.FunctionServiceClient(credentials=credentials)
        functions_request = functions_v2.ListFunctionsRequest(
            parent=f"projects/{proj}/locations/-"
        )
        for func in function_client.list_functions(request=functions_request):
            uri = func.service_config.uri
            if uri:
                infradata.append([proj, "cloudfunction", uri.removeprefix("https://")])
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping Cloud Functions for project {proj} - access denied")

    # Virtual Machines - collect public IPs
    try:
        instances_client = compute_v1.InstancesClient(credentials=credentials)
        instances_request = compute_v1.AggregatedListInstancesRequest(project=proj)
        for _, response in instances_client.aggregated_list(request=instances_request):
            if response.instances:
                for instance in response.instances:
                    for network in instance.network_interfaces:
                        infradata.extend(
                            [proj, "virtualmachine", access_config.nat_i_p]
                            for access_config in network.access_configs
                            if access_config.nat_i_p
                        )
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping Compute Instances for project {proj} - access denied")

    # Cloud Run services
    try:
        run_client = run_v2.ServicesClient(credentials=credentials)
        for region in _CLOUD_RUN_REGIONS:
            parent = f"projects/{proj}/locations/{region}"
            try:
                for service in run_client.list_services(parent=parent):
                    uri = service.uri
                    if uri:
                        infradata.append([proj, "cloudrun", uri.removeprefix("https://")])
            except Forbidden:
                raise
            except GoogleAPICallError:
                # Region doesn't support Cloud Run (or has no services) - not an error.
                continue
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping Cloud Run for project {proj} - access denied")

    # App Engine default service hostname (one application per project, if any)
    try:
        appengine_client = appengine_admin_v1.ApplicationsClient(credentials=credentials)
        application = appengine_client.get_application(name=f"apps/{proj}")
        hostname = application.default_hostname
        if hostname:
            infradata.append([proj, "appengine", hostname.removeprefix("https://")])
    except NotFound:
        pass  # No App Engine application in this project - not an error.
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping App Engine for project {proj} - access denied")

    # GKE cluster control-plane endpoints
    try:
        gke_client = container_v1.ClusterManagerClient(credentials=credentials)
        response = gke_client.list_clusters(parent=f"projects/{proj}/locations/-")
        for cluster in response.clusters:
            if cluster.endpoint:
                infradata.append([proj, "gke", cluster.endpoint])
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping GKE for project {proj} - access denied")

    # Artifact Registry repository hostnames (e.g. REGION-docker.pkg.dev)
    try:
        ar_client = artifactregistry_v1.ArtifactRegistryClient(credentials=credentials)
        for location in ar_client.list_locations(name=f"projects/{proj}"):
            parent = f"projects/{proj}/locations/{location.location_id}"
            for repository in ar_client.list_repositories(parent=parent):
                registry_uri = repository.registry_uri
                if registry_uri:
                    host = registry_uri.removeprefix("https://").split("/", 1)[0]
                    infradata.append([proj, "artifactregistry", host])
    except Forbidden as e:
        if not _api_disabled(e):
            click.echo(f"Skipping Artifact Registry for project {proj} - access denied")

    # Cloud SQL public instance IPs. There's no stable google-cloud-* client
    # for the SQL Admin API, so we call the REST API directly via an
    # AuthorizedSession bound to the same credentials used everywhere else.
    try:
        session = AuthorizedSession(credentials)
        url = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{proj}/instances"
        page_token = None
        while True:
            params = {"pageToken": page_token} if page_token else {}
            resp = session.get(url, params=params)
            if resp.status_code == 403:
                body = resp.json() if resp.content else {}
                message = body.get("error", {}).get("message", "")
                if not _api_disabled(message):
                    click.echo(f"Skipping Cloud SQL for project {proj} - access denied")
                break
            resp.raise_for_status()
            body = resp.json()
            for instance in body.get("items", []):
                for ip in instance.get("ipAddresses", []):
                    if ip.get("type") == "PRIMARY" and ip.get("ipAddress"):
                        infradata.append([proj, "cloudsql", ip["ipAddress"]])
            page_token = body.get("nextPageToken")
            if not page_token:
                break
    except requests.RequestException as e:
        click.echo(f"Skipping Cloud SQL for project {proj} - request failed: {e}")

    return infradata
