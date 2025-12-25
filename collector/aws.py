#!/usr/bin/env python3

import boto3
import click

# Record types we're interested in
_RELEVANT_RECORD_TYPES = frozenset(("A", "AAAA", "CNAME"))


class aws:
    @staticmethod
    def dns(accounts, iamrole):
        """Collect DNS records from AWS accounts via Route53."""
        dnsdata = []

        for aws_account in accounts:
            account_str = str(aws_account)

            if len(account_str) != 12:
                click.echo(
                    f"Please check the AWS Account number {aws_account}. It does not seem to be valid."
                )
                continue

            click.echo(f"Reading DNS data from AWS Account - {account_str}")

            credentials = _assume_role(aws_account, iamrole)
            client = _create_client("route53", credentials)

            hosted_zones = client.list_hosted_zones()["HostedZones"]

            for zone in hosted_zones:
                # Skip private zones
                if zone["Config"]["PrivateZone"]:
                    continue

                records = client.list_resource_record_sets(HostedZoneId=zone["Id"])[
                    "ResourceRecordSets"
                ]

                for record in records:
                    if record["Type"] not in _RELEVANT_RECORD_TYPES:
                        continue

                    record_name = record["Name"]

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

        for aws_account in accounts:
            account_str = str(aws_account)

            if len(account_str) != 12:
                click.echo(
                    f"Please check the AWS Account number {aws_account}. It does not seem to be valid."
                )
                continue

            click.echo(
                f"Getting Infrastructure details from AWS Account - {account_str}"
            )

            credentials = _assume_role(aws_account, iamrole)

            # Get all enabled regions
            ec2_client = _create_client("ec2", credentials)
            regions = [
                r["RegionName"] for r in ec2_client.describe_regions()["Regions"]
            ]

            for region in regions:
                try:
                    _collect_region_infra(aws_account, credentials, region, infradata)
                    click.echo(
                        f"Completed collecting Infrastructure details from account {account_str} in region {region}"
                    )
                except KeyError:
                    continue

        return infradata


def _assume_role(aws_account, iamrole):
    """Assume IAM role and return temporary credentials."""
    sts_client = boto3.client("sts")
    assume_role_response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{aws_account}:role/{iamrole}",
        RoleSessionName="findmytakeover",
    )
    return assume_role_response["Credentials"]


def _create_client(service, credentials, region=None):
    """Create a boto3 client with the given credentials."""
    kwargs = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }
    if region:
        kwargs["region_name"] = region
    return boto3.client(service, **kwargs)


def _collect_region_infra(aws_account, credentials, region, infradata):
    """Collect infrastructure data from a specific region."""

    # EC2 Instances
    ec2_client = _create_client("ec2", credentials, region)
    reservations = ec2_client.describe_instances()["Reservations"]
    for reservation in reservations:
        for instance in reservation["Instances"]:
            for network_interface in instance["NetworkInterfaces"]:
                association = network_interface.get("Association")
                if association:
                    infradata.append([aws_account, "ec2-ip", association["PublicIp"]])
                    infradata.append(
                        [aws_account, "ec2-ip", association["PublicDnsName"]]
                    )

    # Classic Load Balancers
    elb_client = _create_client("elb", credentials, region)
    for lb in elb_client.describe_load_balancers()["LoadBalancerDescriptions"]:
        if lb["Scheme"] == "internet-facing":
            infradata.append([aws_account, "elb", lb["DNSName"]])

    # Application/Network Load Balancers
    elbv2_client = _create_client("elbv2", credentials, region)
    for lb in elbv2_client.describe_load_balancers()["LoadBalancers"]:
        if lb["Scheme"] == "internet-facing":
            infradata.append([aws_account, "elbv2", lb["DNSName"]])

    # Elastic Beanstalk
    beanstalk_client = _create_client("elasticbeanstalk", credentials, region)
    for app in beanstalk_client.describe_applications()["Applications"]:
        environments = beanstalk_client.describe_environments(
            ApplicationName=app["ApplicationName"]
        )["Environments"]
        for env in environments:
            infradata.append([aws_account, "elasticbeanstalk", env["EndpointURL"]])
            infradata.append([aws_account, "elasticbeanstalk", env["CNAME"]])

    # CloudFront Distributions
    cloudfront_client = _create_client("cloudfront", credentials, region)
    distributions = cloudfront_client.list_distributions()
    dist_list = distributions.get("DistributionList", {})
    if dist_list and "Items" in dist_list:
        for dist in dist_list["Items"]:
            infradata.append([aws_account, "cloudfront", dist["DomainName"]])

    # S3 Buckets
    s3_client = _create_client("s3", credentials, region)
    for bucket in s3_client.list_buckets()["Buckets"]:
        infradata.append([aws_account, "s3", bucket["Name"]])

    # RDS Instances
    rds_client = _create_client("rds", credentials, region)
    for db in rds_client.describe_db_instances()["DBInstances"]:
        endpoint = db.get("Endpoint")
        if endpoint:
            infradata.append([aws_account, "rds", endpoint["Address"]])

    # OpenSearch/Elasticsearch Domains
    opensearch_client = _create_client("opensearch", credentials, region)

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

    # API Gateway
    apigateway_client = _create_client("apigatewayv2", credentials, region)
    apis = apigateway_client.get_apis()
    for api in apis.get("Items", []):
        api_endpoint = api.get("ApiEndpoint")
        if api_endpoint:
            infradata.append([aws_account, "apigateway", api_endpoint])
