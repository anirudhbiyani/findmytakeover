#!/usr/bin/env python3

import boto3
import click

from collector import is_cloud_nameserver, zone_key

# Record types we're interested in
_RELEVANT_RECORD_TYPES = frozenset(("A", "AAAA", "CNAME"))

_USE_CLI_CREDS = "default"
_DEFAULT_REGION = "us-east-1"


def _paginate(client, method, result_key, **kwargs):
    """Yield every item across all pages, using a boto3 paginator when one exists."""
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            yield from page.get(result_key, [])
    else:
        yield from getattr(client, method)(**kwargs).get(result_key, [])


class aws:
    @staticmethod
    def dns(accounts, iamrole):
        """Collect DNS records from AWS accounts via Route53."""
        dnsdata = []
        use_default = _is_default_credentials(iamrole)
        accounts = _resolve_accounts(accounts, use_default)

        for aws_account in accounts:
            account_str = str(aws_account)

            if not use_default and len(account_str) != 12:
                click.echo(
                    f"Please check the AWS Account number {aws_account}. It does not seem to be valid."
                )
                continue

            click.echo(f"Reading DNS data from AWS Account - {account_str}")

            client = _create_client("route53", iamrole, aws_account)

            for zone in _paginate(client, "list_hosted_zones", "HostedZones"):
                # Skip private zones
                if zone["Config"]["PrivateZone"]:
                    continue

                zone_name = zone["Name"]
                for record in _paginate(
                    client,
                    "list_resource_record_sets",
                    "ResourceRecordSets",
                    HostedZoneId=zone["Id"],
                ):
                    record_name = record["Name"]

                    # Child NS delegation: dangling if the delegated zone no longer
                    # exists in any scanned account (see infra() hosted-zone rows).
                    # Only flag delegations to a cloud NS pool — the takeover vector.
                    if record["Type"] == "NS" and zone_key(record_name) != zone_key(zone_name):
                        nameservers = [rr["Value"] for rr in record.get("ResourceRecords", [])]
                        if any(is_cloud_nameserver(ns) for ns in nameservers):
                            dnsdata.append([aws_account, record_name, zone_key(record_name)])
                        continue

                    if record["Type"] not in _RELEVANT_RECORD_TYPES:
                        continue

                    # Handle standard resource records
                    resource_records = record.get("ResourceRecords")
                    if resource_records:
                        dnsdata.extend(
                            [aws_account, record_name, rr["Value"]]
                            for rr in resource_records
                        )

                    # Handle alias records
                    alias_target = record.get("AliasTarget")
                    if alias_target:
                        dnsdata.append(
                            [aws_account, record_name, alias_target["DNSName"]]
                        )

        return dnsdata

    @staticmethod
    def infra(accounts, iamrole):
        """Collect infrastructure data from AWS accounts."""
        infradata = []
        use_default = _is_default_credentials(iamrole)
        accounts = _resolve_accounts(accounts, use_default)

        for aws_account in accounts:
            account_str = str(aws_account)

            if not use_default and len(account_str) != 12:
                click.echo(
                    f"Please check the AWS Account number {aws_account}. It does not seem to be valid."
                )
                continue

            click.echo(
                f"Getting Infrastructure details from AWS Account - {account_str}"
            )

            # Account-global services (Route53, S3, CloudFront) — collect once, not per region.
            _collect_global_infra(aws_account, iamrole, infradata)

            ec2_client = _create_client("ec2", iamrole, aws_account)
            regions = [
                r["RegionName"] for r in ec2_client.describe_regions()["Regions"]
            ]

            for region in regions:
                try:
                    _collect_region_infra(aws_account, iamrole, region, infradata)
                    click.echo(
                        f"Completed collecting Infrastructure details from account {account_str} in region {region}"
                    )
                except KeyError:
                    continue

        return infradata


def _is_default_credentials(iamrole):
    """Check if the caller wants to use local CLI credentials."""
    return str(iamrole).strip().lower() == _USE_CLI_CREDS


def _resolve_accounts(accounts, use_default):
    """Return the account list, auto-discovering profiles from ~/.aws/config when using default credentials."""
    if not use_default:
        return accounts

    if accounts:
        return accounts

    profiles = boto3.Session().available_profiles
    click.echo(f"Auto-discovered {len(profiles)} AWS profile(s) from ~/.aws/config: {', '.join(profiles)}")
    return profiles


def _assume_role(aws_account, iamrole):
    """Assume IAM role and return temporary credentials."""
    sts_client = boto3.client("sts")
    assume_role_response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{aws_account}:role/{iamrole}",
        RoleSessionName="findmytakeover",
    )
    return assume_role_response["Credentials"]


def _create_client(service, iamrole, aws_account=None, region=None):
    """Create a boto3 client, using a named CLI profile or assumed role."""
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    if _is_default_credentials(iamrole):
        session = boto3.Session(profile_name=aws_account)
        if not region and not session.region_name:
            kwargs["region_name"] = _DEFAULT_REGION
        return session.client(service, **kwargs)

    credentials = _assume_role(aws_account, iamrole)
    kwargs.update({
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    })
    return boto3.client(service, **kwargs)


def _collect_global_infra(aws_account, iamrole, infradata):
    """Collect account-global resources (Route53 zones, S3, CloudFront) once per account."""

    # Hosted zone names — the "live zones" a delegated NS record is matched against.
    route53_client = _create_client("route53", iamrole, aws_account)
    for zone in _paginate(route53_client, "list_hosted_zones", "HostedZones"):
        infradata.append([aws_account, "hostedzone", zone_key(zone["Name"])])

    # S3 Buckets (global)
    s3_client = _create_client("s3", iamrole, aws_account)
    for bucket in s3_client.list_buckets()["Buckets"]:
        infradata.append([aws_account, "s3", bucket["Name"]])

    # CloudFront Distributions (global) — DistributionList is a dict, not a list,
    # so iterate paginator pages directly rather than via _paginate.
    cloudfront_client = _create_client("cloudfront", iamrole, aws_account)
    for page in cloudfront_client.get_paginator("list_distributions").paginate():
        for dist in page.get("DistributionList", {}).get("Items", []):
            infradata.append([aws_account, "cloudfront", dist["DomainName"]])


def _collect_region_infra(aws_account, iamrole, region, infradata):
    """Collect infrastructure data from a specific region."""

    # EC2 Instances
    ec2_client = _create_client("ec2", iamrole, aws_account, region)
    for reservation in _paginate(ec2_client, "describe_instances", "Reservations"):
        for instance in reservation["Instances"]:
            for network_interface in instance["NetworkInterfaces"]:
                association = network_interface.get("Association")
                if association:
                    infradata.append([aws_account, "ec2-ip", association["PublicIp"]])
                    infradata.append(
                        [aws_account, "ec2-ip", association["PublicDnsName"]]
                    )

    # Classic Load Balancers
    elb_client = _create_client("elb", iamrole, aws_account, region)
    for lb in _paginate(elb_client, "describe_load_balancers", "LoadBalancerDescriptions"):
        if lb["Scheme"] == "internet-facing":
            infradata.append([aws_account, "elb", lb["DNSName"]])

    # Application/Network Load Balancers
    elbv2_client = _create_client("elbv2", iamrole, aws_account, region)
    for lb in _paginate(elbv2_client, "describe_load_balancers", "LoadBalancers"):
        if lb["Scheme"] == "internet-facing":
            infradata.append([aws_account, "elbv2", lb["DNSName"]])

    # Elastic Beanstalk
    beanstalk_client = _create_client("elasticbeanstalk", iamrole, aws_account, region)
    for app in beanstalk_client.describe_applications()["Applications"]:
        environments = beanstalk_client.describe_environments(
            ApplicationName=app["ApplicationName"]
        )["Environments"]
        for env in environments:
            infradata.append([aws_account, "elasticbeanstalk", env["EndpointURL"]])
            infradata.append([aws_account, "elasticbeanstalk", env["CNAME"]])

    # RDS Instances
    rds_client = _create_client("rds", iamrole, aws_account, region)
    for db in _paginate(rds_client, "describe_db_instances", "DBInstances"):
        endpoint = db.get("Endpoint")
        if endpoint:
            infradata.append([aws_account, "rds", endpoint["Address"]])

    # OpenSearch/Elasticsearch Domains
    opensearch_client = _create_client("opensearch", iamrole, aws_account, region)

    for engine_type in ("OpenSearch", "Elasticsearch"):
        domains = opensearch_client.list_domain_names(EngineType=engine_type)[
            "DomainNames"
        ]
        for domain in domains:
            domain_info = opensearch_client.describe_domain(
                DomainName=domain["DomainName"]
            )
            endpoint = domain_info["DomainStatus"].get("Endpoint")
            if endpoint:
                infradata.append([aws_account, "opensearch", endpoint])

    # API Gateway (v2) — manual NextToken pagination (no boto3 paginator)
    apigateway_client = _create_client("apigatewayv2", iamrole, aws_account, region)
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        apis = apigateway_client.get_apis(**kwargs)
        for api in apis.get("Items", []):
            api_endpoint = api.get("ApiEndpoint")
            if api_endpoint:
                infradata.append([aws_account, "apigateway", api_endpoint])
        next_token = apis.get("NextToken")
        if not next_token:
            break
