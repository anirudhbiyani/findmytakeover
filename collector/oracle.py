#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import oci
import click

from collector import is_cloud_nameserver, zone_key, MAX_WORKERS

_RELEVANT_RECORD_TYPES = frozenset(("A", "AAAA", "CNAME"))
_USE_CLI_CREDS = "default"


def _is_default_credentials(cred):
    return isinstance(cred, str) and cred.strip().lower() == _USE_CLI_CREDS


def _load_config(cred):
    """OCI config. 'default' uses ~/.oci/config DEFAULT profile; otherwise cred is a path to a config file."""
    if _is_default_credentials(cred):
        return oci.config.from_file()
    return oci.config.from_file(file_location=cred)


def _resolve_compartments(accounts, config, use_default):
    """Compartment OCIDs to scan. Auto-discovers the tenancy + all active sub-compartments."""
    if not use_default or accounts:
        return accounts

    tenancy = config["tenancy"]
    identity = oci.identity.IdentityClient(config)
    discovered = [tenancy]
    discovered.extend(
        c.id
        for c in oci.pagination.list_call_get_all_results(
            identity.list_compartments,
            tenancy,
            compartment_id_in_subtree=True,
            lifecycle_state="ACTIVE",
        ).data
    )
    click.echo(f"Auto-discovered {len(discovered)} OCI compartment(s) from CLI config")
    return discovered


def _resolve_regions(config):
    """Region names to scan. Auto-discovers every region the tenancy is subscribed to."""
    identity = oci.identity.IdentityClient(config)
    try:
        subscriptions = identity.list_region_subscriptions(config["tenancy"]).data
    except oci.exceptions.ServiceError as e:
        click.echo(
            f"Could not list OCI region subscriptions - {e.status} {e.code}; scanning default region only"
        )
        return [config["region"]]

    regions = [s.region_name for s in subscriptions if s.status == "READY"]
    if not regions:
        regions = [config["region"]]
    click.echo(f"Auto-discovered {len(regions)} OCI region(s): {', '.join(regions)}")
    return regions


def _region_config(config, region):
    """Copy of the OCI config with region overridden, for building a client scoped to that region."""
    region_config = dict(config)
    region_config["region"] = region
    return region_config


def _try(label, fn):
    """Call fn(), returning [] and logging on ServiceError so one missing/denied service doesn't abort the run."""
    try:
        return fn()
    except oci.exceptions.ServiceError as e:
        click.echo(f"Skipping {label} - {e.status} {e.code}")
        return []


def _host_from_url(value):
    """Strip scheme/port/path from a URL or bare host string, returning a DNS-matchable hostname."""
    if not value:
        return None
    candidate = value if "://" in value else f"//{value}"
    return urlparse(candidate).hostname


def _zone_records(dns_client, zone_id):
    """All records in a zone, following opc-next-page pagination."""
    records = []
    page = None
    while True:
        resp = dns_client.get_zone_records(zone_id, page=page)
        records.extend(resp.data.items)
        if not resp.next_page:
            break
        page = resp.next_page
    return records


def _autonomous_database_rows(database_client, compartment):
    """Public connection hostnames for Autonomous Databases in a compartment."""
    rows = []
    for db in oci.pagination.list_call_get_all_results(
        database_client.list_autonomous_databases, compartment_id=compartment
    ).data:
        if db.public_endpoint:
            host = _host_from_url(db.public_endpoint)
            if host:
                rows.append([compartment, "database", zone_key(host)])

        connection_urls = db.connection_urls
        if connection_urls and connection_urls.sql_dev_web_url:
            host = _host_from_url(connection_urls.sql_dev_web_url)
            if host:
                rows.append([compartment, "database", zone_key(host)])
    return rows


def _db_system_rows(database_client, compartment):
    """Public hostnames for (non-Autonomous) DB Systems in a compartment."""
    rows = []
    for db_system in oci.pagination.list_call_get_all_results(
        database_client.list_db_systems, compartment_id=compartment
    ).data:
        if db_system.scan_dns_name:
            rows.append([compartment, "database", zone_key(db_system.scan_dns_name)])
        if db_system.hostname and db_system.domain:
            rows.append(
                [compartment, "database", zone_key(f"{db_system.hostname}.{db_system.domain}")]
            )
    return rows


def _function_rows(functions_client, compartment):
    """Invoke-endpoint hostnames for Functions in a compartment."""
    rows = []
    for app in oci.pagination.list_call_get_all_results(
        functions_client.list_applications, compartment_id=compartment
    ).data:
        try:
            functions = oci.pagination.list_call_get_all_results(
                functions_client.list_functions, application_id=app.id
            ).data
        except oci.exceptions.ServiceError as e:
            click.echo(f"Skipping functions in application {app.id} - {e.status} {e.code}")
            continue

        for fn in functions:
            host = _host_from_url(fn.invoke_endpoint)
            if host:
                rows.append([compartment, "function", host])
    return rows


def _container_instance_rows(container_instance_client, network_client, compartment):
    """Public IPs of Container Instances in a compartment, if any are exposed."""
    rows = []
    for ci in oci.pagination.list_call_get_all_results(
        container_instance_client.list_container_instances, compartment_id=compartment
    ).data:
        try:
            full = container_instance_client.get_container_instance(ci.id).data
        except oci.exceptions.ServiceError as e:
            click.echo(f"Skipping container instance {ci.id} - {e.status} {e.code}")
            continue

        for vnic_ref in full.vnics or []:
            try:
                vnic = network_client.get_vnic(vnic_ref.vnic_id).data
            except oci.exceptions.ServiceError as e:
                click.echo(f"Skipping VNIC {vnic_ref.vnic_id} - {e.status} {e.code}")
                continue
            if vnic and vnic.public_ip:
                rows.append([compartment, "containerinstance", vnic.public_ip])
    return rows


def _collect_region_compartment_infra(config, region, compartment, namespace):
    """Collect infrastructure rows for one (region, compartment) pair (returns rows)."""
    click.echo(f"Getting Infrastructure details from Oracle Cloud compartment {compartment} in region {region}")
    region_config = _region_config(config, region)
    tag = f"{region}/{compartment}"

    dns_client = oci.dns.DnsClient(region_config)
    network_client = oci.core.VirtualNetworkClient(region_config)
    lb_client = oci.load_balancer.LoadBalancerClient(region_config)
    nlb_client = oci.network_load_balancer.NetworkLoadBalancerClient(region_config)
    identity_client = oci.identity.IdentityClient(region_config)
    object_storage = oci.object_storage.ObjectStorageClient(region_config)
    database_client = oci.database.DatabaseClient(region_config)
    gateway_client = oci.apigateway.GatewayClient(region_config)
    functions_client = oci.functions.FunctionsManagementClient(region_config)
    container_instance_client = oci.container_instances.ContainerInstanceClient(region_config)

    rows = []

    # DNS zone names — the "live zones" a delegated NS record is matched against.
    rows.extend(_try(f"OCI dnszone [{tag}]", lambda: [
        [compartment, "dnszone", zone_key(zone.name)]
        for zone in oci.pagination.list_call_get_all_results(
            dns_client.list_zones, compartment_id=compartment
        ).data
    ]))

    # Reserved public IPs (region scope)
    rows.extend(_try(f"OCI reserved publicip [{tag}]", lambda: [
        [compartment, "publicip", ip.ip_address]
        for ip in oci.pagination.list_call_get_all_results(
            network_client.list_public_ips, scope="REGION", compartment_id=compartment
        ).data
        if ip.ip_address
    ]))

    # Ephemeral public IPs (AD scope) — e.g. those attached to instances
    def _ephemeral_ips():
        out = []
        for ad in identity_client.list_availability_domains(compartment).data:
            for ip in oci.pagination.list_call_get_all_results(
                network_client.list_public_ips,
                scope="AVAILABILITY_DOMAIN",
                compartment_id=compartment,
                availability_domain=ad.name,
                lifetime="EPHEMERAL",
            ).data:
                if ip.ip_address:
                    out.append([compartment, "publicip", ip.ip_address])
        return out

    rows.extend(_try(f"OCI ephemeral publicip [{tag}]", _ephemeral_ips))

    # Load balancers (classic)
    rows.extend(_try(f"OCI loadbalancer [{tag}]", lambda: [
        [compartment, "loadbalancer", ip.ip_address]
        for lb in oci.pagination.list_call_get_all_results(
            lb_client.list_load_balancers, compartment_id=compartment
        ).data
        for ip in (lb.ip_addresses or [])
        if ip.ip_address
    ]))

    # Network load balancers — distinct service from the classic LB above
    rows.extend(_try(f"OCI networkloadbalancer [{tag}]", lambda: [
        [compartment, "networkloadbalancer", ip.ip_address]
        for nlb in oci.pagination.list_call_get_all_results(
            nlb_client.list_network_load_balancers, compartment_id=compartment
        ).data
        if not nlb.is_private
        for ip in (nlb.ip_addresses or [])
        if ip.is_public and ip.ip_address
    ]))

    # Object storage buckets (bucket data is regional even though the namespace is tenant-wide)
    if namespace:
        rows.extend(_try(f"OCI bucket [{tag}]", lambda: [
            [compartment, "bucket", bucket.name]
            for bucket in oci.pagination.list_call_get_all_results(
                object_storage.list_buckets, namespace, compartment
            ).data
        ]))

    # Autonomous Database public connection hostnames
    rows.extend(_try(
        f"OCI autonomous database [{tag}]",
        lambda: _autonomous_database_rows(database_client, compartment),
    ))

    # DB Systems (VM/BM) — SCAN name and/or hostname.domain
    rows.extend(_try(
        f"OCI db system [{tag}]",
        lambda: _db_system_rows(database_client, compartment),
    ))

    # API Gateway hostnames (public gateways only)
    rows.extend(_try(f"OCI apigateway [{tag}]", lambda: [
        [compartment, "apigateway", zone_key(gw.hostname)]
        for gw in oci.pagination.list_call_get_all_results(
            gateway_client.list_gateways, compartment_id=compartment
        ).data
        if gw.hostname and gw.endpoint_type == "PUBLIC"
    ]))

    # Functions invoke endpoints
    rows.extend(_try(
        f"OCI function [{tag}]",
        lambda: _function_rows(functions_client, compartment),
    ))

    # Container instances exposing a public IP
    rows.extend(_try(
        f"OCI containerinstance [{tag}]",
        lambda: _container_instance_rows(container_instance_client, network_client, compartment),
    ))

    return rows


class oracle:
    @staticmethod
    def dns(accounts, cred):
        """Collect DNS records from Oracle Cloud (OCI) DNS zones."""
        config = _load_config(cred)
        accounts = _resolve_compartments(accounts, config, _is_default_credentials(cred))
        dns_client = oci.dns.DnsClient(config)
        dnsdata = []

        for compartment in accounts:
            click.echo(f"Reading DNS data from Oracle Cloud compartment - {compartment}")
            try:
                zones = oci.pagination.list_call_get_all_results(
                    dns_client.list_zones, compartment_id=compartment
                ).data
            except oci.exceptions.ServiceError as e:
                click.echo(f"Skipping compartment {compartment} - {e.status} {e.code}")
                continue

            for zone in zones:
                for record in _zone_records(dns_client, zone.id):
                    rtype = record.rtype
                    name = record.domain

                    if rtype in _RELEVANT_RECORD_TYPES:
                        value = record.rdata.rstrip(".") if rtype == "CNAME" else record.rdata
                        dnsdata.append([compartment, name, value])
                    # Child NS delegation to a cloud NS pool → dangling if the
                    # delegated zone is not in the inventory (see infra()).
                    elif rtype == "NS" and zone_key(name) != zone_key(zone.name):
                        if is_cloud_nameserver(record.rdata):
                            dnsdata.append([compartment, name, zone_key(name)])

        return dnsdata

    @staticmethod
    def infra(accounts, cred):
        """Collect infrastructure endpoints from Oracle Cloud (OCI) compartments, across every
        region the tenancy is subscribed to."""
        config = _load_config(cred)
        accounts = _resolve_compartments(accounts, config, _is_default_credentials(cred))
        regions = _resolve_regions(config)

        # Object-storage namespace is tenant-wide (same value in every region); fetch once.
        try:
            namespace = oci.object_storage.ObjectStorageClient(config).get_namespace().data
        except oci.exceptions.ServiceError as e:
            click.echo(f"Skipping OCI object storage - {e.status} {e.code}")
            namespace = None

        # Regions/compartments are independent and I/O-bound — collect them concurrently.
        # pool.map preserves task order, so results stay deterministic despite parallel execution.
        tasks = [(region, compartment) for region in regions for compartment in accounts]
        infradata = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for rows in pool.map(
                lambda t: _collect_region_compartment_infra(config, t[0], t[1], namespace), tasks
            ):
                infradata.extend(rows)

        return infradata
