#!/usr/bin/env python3

import oci
import click

from collector import is_cloud_nameserver, zone_key

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
        """Collect infrastructure endpoints from Oracle Cloud (OCI) compartments."""
        config = _load_config(cred)
        accounts = _resolve_compartments(accounts, config, _is_default_credentials(cred))
        dns_client = oci.dns.DnsClient(config)
        network_client = oci.core.VirtualNetworkClient(config)
        lb_client = oci.load_balancer.LoadBalancerClient(config)
        identity_client = oci.identity.IdentityClient(config)
        object_storage = oci.object_storage.ObjectStorageClient(config)
        infradata = []

        # Object-storage namespace is account-wide; skip buckets gracefully if denied.
        try:
            namespace = object_storage.get_namespace().data
        except oci.exceptions.ServiceError as e:
            click.echo(f"Skipping OCI object storage - {e.status} {e.code}")
            namespace = None

        for compartment in accounts:
            click.echo(
                f"Getting Infrastructure details from Oracle Cloud compartment - {compartment}"
            )
            try:
                # DNS zone names — the "live zones" a delegated NS record is matched against.
                for zone in oci.pagination.list_call_get_all_results(
                    dns_client.list_zones, compartment_id=compartment
                ).data:
                    infradata.append([compartment, "dnszone", zone_key(zone.name)])

                # Reserved public IPs (region scope)
                for ip in oci.pagination.list_call_get_all_results(
                    network_client.list_public_ips, scope="REGION", compartment_id=compartment
                ).data:
                    if ip.ip_address:
                        infradata.append([compartment, "publicip", ip.ip_address])

                # Ephemeral public IPs (AD scope) — e.g. those attached to instances
                for ad in identity_client.list_availability_domains(compartment).data:
                    for ip in oci.pagination.list_call_get_all_results(
                        network_client.list_public_ips,
                        scope="AVAILABILITY_DOMAIN",
                        compartment_id=compartment,
                        availability_domain=ad.name,
                        lifetime="EPHEMERAL",
                    ).data:
                        if ip.ip_address:
                            infradata.append([compartment, "publicip", ip.ip_address])

                # Load balancers
                for lb in oci.pagination.list_call_get_all_results(
                    lb_client.list_load_balancers, compartment_id=compartment
                ).data:
                    for ip in (lb.ip_addresses or []):
                        if ip.ip_address:
                            infradata.append([compartment, "loadbalancer", ip.ip_address])

                # Object storage buckets
                if namespace:
                    for bucket in oci.pagination.list_call_get_all_results(
                        object_storage.list_buckets, namespace, compartment
                    ).data:
                        infradata.append([compartment, "bucket", bucket.name])
            except oci.exceptions.ServiceError as e:
                click.echo(f"Skipping compartment {compartment} - {e.status} {e.code}")

        # ponytail: scans the config's default region only. To cover all regions,
        # iterate identity.list_region_subscriptions and rebuild clients per region.
        return infradata
