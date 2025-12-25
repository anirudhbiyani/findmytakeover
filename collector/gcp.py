#!/usr/bin/env python3

from google.cloud import dns
from google.oauth2 import service_account
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import functions_v2
import click

# Record types we're interested in for DNS
_A_AAAA_TYPES = frozenset(("A", "AAAA"))
_CNAME_TYPE = "CNAME"


class gcp:
    @staticmethod
    def dns(projects, path):
        """Collect DNS records from GCP projects."""
        credentials = service_account.Credentials.from_service_account_file(path)
        dnsdata = []

        for proj in projects:
            click.echo(f"Reading DNS data from Google Cloud Project - {proj}")
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

        return dnsdata

    @staticmethod
    def infra(projects, path):
        """Collect infrastructure data from GCP projects."""
        credentials = service_account.Credentials.from_service_account_file(path)
        infradata = []

        # Pre-create clients that can be reused (they use per-request project context)
        forwarding_rules_client = compute_v1.ForwardingRulesClient(
            credentials=credentials
        )
        function_client = functions_v2.FunctionServiceClient(credentials=credentials)
        instances_client = compute_v1.InstancesClient(credentials=credentials)

        for proj in projects:
            click.echo(
                f"Getting Infrastructure details from Google Cloud Project - {proj}"
            )

            # Cloud Storage Buckets
            storage_client = storage.Client(credentials=credentials, project=proj)
            infradata.extend(
                [proj, "bucket", bucket.name]
                for bucket in storage_client.list_buckets()
            )

            # LoadBalancer IP Addresses
            for _, response in forwarding_rules_client.aggregated_list(project=proj):
                if response.forwarding_rules:
                    infradata.extend(
                        [proj, "loadbalancer", rule.IP_address]
                        for rule in response.forwarding_rules
                    )

            # Cloud Functions
            functions_request = functions_v2.ListFunctionsRequest(
                parent=f"projects/{proj}/locations/-"
            )
            for func in function_client.list_functions(request=functions_request):
                uri = func.service_config.uri
                if uri:
                    infradata.append(
                        [proj, "cloudfunction", uri.removeprefix("https://")]
                    )

            # Virtual Machines - collect public IPs
            instances_request = compute_v1.AggregatedListInstancesRequest(project=proj)
            for _, response in instances_client.aggregated_list(
                request=instances_request
            ):
                if response.instances:
                    for instance in response.instances:
                        for network in instance.network_interfaces:
                            infradata.extend(
                                [proj, "virtualmachine", access_config.nat_i_p]
                                for access_config in network.access_configs
                                if access_config.nat_i_p
                            )

        return infradata
