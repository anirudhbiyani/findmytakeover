#!/usr/bin/env python3

from collections import defaultdict
from google.cloud import dns
from google.oauth2 import service_account
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import functions_v2
import click

class gcp:
    def dns(projects, path):
        dnsdata = []
        credentials = service_account.Credentials.from_service_account_file(path)

        for proj in projects:
            click.echo("Reading DNS data from Google Cloud Project - " + str(proj))
            dns_client = dns.client.Client(credentials=credentials, project=proj)
            managed_zones = dns_client.list_zones()
            for managed_zone in managed_zones:
                dns_record_client = dns.zone.ManagedZone(name=managed_zone.name, client=dns_client)
                resource_record_sets = dns_record_client.list_resource_record_sets()

                for resource_record_set in resource_record_sets:
                    if resource_record_set.record_type == "A" or resource_record_set.record_type == "AAAA":
                        for ip_address in resource_record_set.rrdatas:
                            dnsdata.append([proj, resource_record_set.name[:-1], ip_address])
                    
                    if resource_record_set.record_type == "CNAME":
                        for ip_address in resource_record_set.rrdatas:
                            dnsdata.append([proj, resource_record_set.name[:-1], ip_address[:-1]])
        return dnsdata

    def infra(projects, path):
        infradata = []
       
        # Cloud Buckets
        credentials = service_account.Credentials.from_service_account_file(path)
        for proj in projects:
            click.echo("Getting Infrastructure details from Google Cloud Project - " + str(proj))
            storage_client = storage.Client(credentials=credentials, project=proj)
            result = storage_client.list_buckets()
            for i in result:
                response = storage_client.get_bucket(i)
                infradata.append([proj, "bucket", response.name])
        
        # LoadBalancer IP Address
            compute_client = compute_v1.ForwardingRulesClient(credentials=credentials)    
            frontend = compute_client.aggregated_list(project=proj)
            for zone, response in frontend:
               if response.forwarding_rules:
                   for i in response.forwarding_rules:
                       infradata.append([proj, "loadbalancer", i.I_p_address])
        
        # Cloud Functions
            function_client = functions_v2.FunctionServiceClient(credentials=credentials)
            URL = function_client.list_functions(request=functions_v2.ListFunctionsRequest(parent="projects/"+proj + "/locations/-"))
            for i in URL.functions:
                infradata.append([proj, "cloudfunction", str(i.service_config.uri).replace("https://", "")])
        
        # Virtual Machines
            compute_client = compute_v1.InstancesClient(credentials=credentials).aggregated_list(request=compute_v1.AggregatedListInstancesRequest(project=proj))
            all_instances = defaultdict(list)
            for zone, response in compute_client:
                if response.instances:
                    all_instances[zone].extend(response.instances)
                    for instance in response.instances:
                        for network in instance.network_interfaces:
                            for ip in network.access_configs:
                                infradata.append([proj, "virtualmachine", ip.nat_i_p])

        return infradata    