#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import boto3
import click
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError

from collector import (
    MAX_WORKERS,
    SECONDARY_RECORD_TYPES,
    is_cloud_nameserver,
    note_error,
    secondary_targets,
    zone_key,
)

_PROVIDER = "Amazon Web Services"

# Record types we're interested in
_RELEVANT_RECORD_TYPES = frozenset(("A", "AAAA", "CNAME"))

_USE_CLI_CREDS = "default"
_DEFAULT_REGION = "us-east-1"

# Global Accelerator has no regional control plane — its API is only served
# out of us-west-2, regardless of where the accelerator's endpoints live.
_GLOBALACCELERATOR_REGION = "us-west-2"

# Failures that mean "couldn't collect this", as opposed to bugs. They're
# recorded (see collector.note_error) rather than aborting the scan, because a
# missing service is a gap in inventory, not a reason to lose every other one.
_COLLECTION_ERRORS = (ClientError, BotoCoreError, KeyError)


def _paginate(client, method, result_key, **kwargs):
    """Yield every item across all pages, using a boto3 paginator when one exists."""
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            yield from page.get(result_key, [])
    else:
        yield from getattr(client, method)(**kwargs).get(result_key, [])


def _strip_url(value):
    """Strip scheme and any trailing path/slash, leaving a bare DNS-matchable hostname."""
    if not value:
        return value
    return value.removeprefix("https://").removeprefix("http://").split("/")[0]


class aws:
    @staticmethod
    def dns(accounts, iamrole):
        """Collect DNS records from AWS accounts via Route53."""
        use_default = _is_default_credentials(iamrole)
        accounts = _resolve_accounts(accounts, use_default)

        dnsdata = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for rows in pool.map(
                lambda a: _dns_for_account(a, iamrole, use_default), accounts
            ):
                dnsdata.extend(rows)
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

            try:
                ec2_client = _create_client("ec2", iamrole, aws_account)
                regions = [
                    r["RegionName"] for r in ec2_client.describe_regions()["Regions"]
                ]
            except _COLLECTION_ERRORS as e:
                note_error(_PROVIDER, account_str, "region list (all regional resources)", e)
                continue

            # Regions are independent and I/O-bound — collect them concurrently.
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                for region_rows in pool.map(
                    lambda region: _collect_region_infra(aws_account, iamrole, region),
                    regions,
                ):
                    infradata.extend(region_rows)

        return infradata


def _dns_for_account(aws_account, iamrole, use_default):
    """Collect Route53 DNS records for a single account (returns rows)."""
    account_str = str(aws_account)
    if not use_default and len(account_str) != 12:
        click.echo(
            f"Please check the AWS Account number {aws_account}. It does not seem to be valid."
        )
        return []

    click.echo(f"Reading DNS data from AWS Account - {account_str}")
    dnsdata = []
    try:
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

                # MX / SRV / SPF: the hostnames they name, tagged with the type.
                if record["Type"] in SECONDARY_RECORD_TYPES:
                    for rr in record.get("ResourceRecords", []):
                        dnsdata.extend(
                            [aws_account, record_name, target, record["Type"]]
                            for target in secondary_targets(record["Type"], rr["Value"])
                        )
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
                    dnsdata.append([aws_account, record_name, alias_target["DNSName"]])
    except _COLLECTION_ERRORS as e:
        note_error(_PROVIDER, account_str, "Route 53 records", e)

    return dnsdata


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


@lru_cache(maxsize=None)
def _home_region(iamrole, aws_account):
    """The region the account's credentials live in: the profile's region with
    default credentials, else the environment's. GovCloud users set a
    us-gov-* region here, and everything partition-specific follows from it."""
    profile = aws_account if _is_default_credentials(iamrole) else None
    return boto3.Session(profile_name=profile).region_name or _DEFAULT_REGION


@lru_cache(maxsize=None)
def _partition(region):
    """AWS partition for a region: "aws", or "aws-us-gov" for GovCloud."""
    return boto3.Session().get_partition_for_region(region)


def _offered_in(service, region):
    """True if `service` exists in the region's partition (CloudFront and
    Global Accelerator don't exist in GovCloud)."""
    return bool(
        boto3.Session().get_available_regions(service, _partition(region), allow_non_regional=True)
    )


@lru_cache(maxsize=None)
def _assume_role(aws_account, iamrole):
    """Assume IAM role and return temporary credentials (cached per account for the run)."""
    region = _home_region(iamrole, aws_account)
    sts_client = boto3.client("sts", region_name=region)
    assume_role_response = sts_client.assume_role(
        RoleArn=f"arn:{_partition(region)}:iam::{aws_account}:role/{iamrole}",
        RoleSessionName="findmytakeover",
    )
    return assume_role_response["Credentials"]


def _create_client(service, iamrole, aws_account=None, region=None):
    """Create a boto3 client, using a named CLI profile or assumed role."""
    kwargs = {"region_name": region or _home_region(iamrole, aws_account)}

    if _is_default_credentials(iamrole):
        return boto3.Session(profile_name=aws_account).client(service, **kwargs)

    credentials = _assume_role(aws_account, iamrole)
    kwargs.update({
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    })
    return boto3.client(service, **kwargs)


def _collect_global_infra(aws_account, iamrole, infradata):
    """Collect account-global resources (Route53 zones, S3, CloudFront) once per account."""
    home = _home_region(iamrole, aws_account)

    def make(service, region=None):
        return _create_client(service, iamrole, aws_account, region=region)

    def hosted_zones():
        # Hosted zone names — the "live zones" a delegated NS record is matched against.
        for zone in _paginate(make("route53"), "list_hosted_zones", "HostedZones"):
            yield zone_key(zone["Name"])

    def s3_buckets():
        # Bucket names; findmytakeover reduces S3 endpoint hostnames to these.
        for bucket in make("s3").list_buckets()["Buckets"]:
            yield bucket["Name"]

    def cloudfront():
        # DistributionList is a dict, not a list, so iterate pages directly.
        for page in make("cloudfront").get_paginator("list_distributions").paginate():
            for dist in page.get("DistributionList", {}).get("Items", []):
                yield dist["DomainName"]

    def globalaccelerator():
        # Control plane only exists in us-west-2.
        client = make("globalaccelerator", region=_GLOBALACCELERATOR_REGION)
        for accelerator in _paginate(client, "list_accelerators", "Accelerators"):
            yield accelerator.get("DnsName")

    collectors = [("hostedzone", hosted_zones), ("s3", s3_buckets)]
    if _offered_in("cloudfront", home):
        collectors.append(("cloudfront", cloudfront))
    if _offered_in("globalaccelerator", home):
        collectors.append(("globalaccelerator", globalaccelerator))

    for label, collect in collectors:
        try:
            infradata.extend(
                [aws_account, label, _strip_url(value)] for value in collect() if value
            )
        except _COLLECTION_ERRORS as e:
            note_error(_PROVIDER, aws_account, label, e)


# --- Regional collectors. Each takes a client factory and yields endpoint
# values (hostnames or IPs); _collect_region_infra runs each in isolation so a
# denied or unavailable service only costs its own rows.

def _public_ips(make):
    """Every public address the region holds for the account: all Elastic IPs
    (attached or not) and every public IPv4/IPv6 on any network interface —
    instances, NAT gateways, load balancers, ECS tasks, Lambda and so on."""
    ec2 = make("ec2")
    for address in _paginate(ec2, "describe_addresses", "Addresses"):
        yield address.get("PublicIp")
    for eni in _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces"):
        association = eni.get("Association") or {}
        yield association.get("PublicIp")
        yield association.get("PublicDnsName")
        for private in eni.get("PrivateIpAddresses", []):
            yield (private.get("Association") or {}).get("PublicIp")
        for ipv6 in eni.get("Ipv6Addresses", []):
            yield ipv6.get("Ipv6Address")


def _classic_elbs(make):
    for lb in _paginate(make("elb"), "describe_load_balancers", "LoadBalancerDescriptions"):
        if lb.get("Scheme") == "internet-facing":
            yield lb.get("DNSName")


def _elbv2s(make):
    for lb in _paginate(make("elbv2"), "describe_load_balancers", "LoadBalancers"):
        if lb.get("Scheme") == "internet-facing":
            yield lb.get("DNSName")


def _beanstalk(make):
    client = make("elasticbeanstalk")
    for app in client.describe_applications()["Applications"]:
        environments = client.describe_environments(
            ApplicationName=app["ApplicationName"]
        )["Environments"]
        for env in environments:
            yield env.get("EndpointURL")
            yield env.get("CNAME")


def _rds(make):
    for db in _paginate(make("rds"), "describe_db_instances", "DBInstances"):
        yield (db.get("Endpoint") or {}).get("Address")


def _opensearch(make):
    client = make("opensearch")
    for engine_type in ("OpenSearch", "Elasticsearch"):
        for domain in client.list_domain_names(EngineType=engine_type)["DomainNames"]:
            status = client.describe_domain(DomainName=domain["DomainName"])["DomainStatus"]
            yield status.get("Endpoint")


def _apigateway_v1(make):
    """REST APIs ({id}.execute-api.{region}.amazonaws.com) and the targets
    custom domain names are CNAMEd to (d-xxx.execute-api / dxxx.cloudfront.net)."""
    client = make("apigateway")
    region = client.meta.region_name
    for api in _paginate(client, "get_rest_apis", "items"):
        yield f"{api['id']}.execute-api.{region}.amazonaws.com"
    for domain in _paginate(client, "get_domain_names", "items"):
        yield domain.get("regionalDomainName")
        yield domain.get("distributionDomainName")


def _apigateway_v2(make):
    """HTTP/WebSocket APIs (ApiEndpoint is a URL) and custom domain targets."""
    client = make("apigatewayv2")
    for api in _paginate(client, "get_apis", "Items"):
        yield api.get("ApiEndpoint")
    for domain in _paginate(client, "get_domain_names", "Items"):
        for config in domain.get("DomainNameConfigurations", []):
            yield config.get("ApiGatewayDomainName")


def _lambda_urls(make):
    client = make("lambda")
    for function in _paginate(client, "list_functions", "Functions"):
        try:
            url_config = client.get_function_url_config(FunctionName=function["FunctionName"])
        except client.exceptions.ResourceNotFoundException:
            # No Function URL configured for this function — not an error.
            continue
        yield url_config.get("FunctionUrl")


def _eks(make):
    client = make("eks")
    for cluster_name in _paginate(client, "list_clusters", "clusters"):
        yield client.describe_cluster(name=cluster_name)["cluster"].get("endpoint")


def _ecr(make):
    # repositoryUri is "<host>/<repo-name>"; _strip_url keeps the registry host.
    for repo in _paginate(make("ecr"), "describe_repositories", "repositories"):
        yield repo.get("repositoryUri")


def _amplify(make):
    for app in _paginate(make("amplify"), "list_apps", "apps"):
        yield app.get("defaultDomain")


def _apprunner(make):
    for service in _paginate(make("apprunner"), "list_services", "ServiceSummaryList"):
        yield service.get("ServiceUrl")


def _cognito(make):
    """User pool hosted-UI domains: the prefix domain's amazoncognito.com host,
    and the CloudFront distribution a custom domain is CNAMEd to."""
    client = make("cognito-idp")
    region = client.meta.region_name
    for pool in _paginate(client, "list_user_pools", "UserPools", MaxResults=60):
        detail = client.describe_user_pool(UserPoolId=pool["Id"])["UserPool"]
        if detail.get("Domain"):
            yield f"{detail['Domain']}.auth.{region}.amazoncognito.com"
        if detail.get("CustomDomain"):
            description = client.describe_user_pool_domain(Domain=detail["CustomDomain"])
            yield description["DomainDescription"].get("CloudFrontDistribution")


_REGIONAL_COLLECTORS = (
    ("public-ip", _public_ips),
    ("elb", _classic_elbs),
    ("elbv2", _elbv2s),
    ("elasticbeanstalk", _beanstalk),
    ("rds", _rds),
    ("opensearch", _opensearch),
    ("apigateway", _apigateway_v1),
    ("apigatewayv2", _apigateway_v2),
    ("lambda-url", _lambda_urls),
    ("eks", _eks),
    ("ecr", _ecr),
    ("amplify", _amplify),
    ("apprunner", _apprunner),
    ("cognito", _cognito),
)


def _collect_region_infra(aws_account, iamrole, region):
    """Collect infrastructure data from a specific region (returns rows)."""

    def make(service):
        return _create_client(service, iamrole, aws_account, region)

    infradata = []
    for label, collect in _REGIONAL_COLLECTORS:
        try:
            infradata.extend(
                [aws_account, label, _strip_url(value)] for value in collect(make) if value
            )
        except EndpointConnectionError:
            # The service isn't offered in this region — nothing to collect.
            pass
        except _COLLECTION_ERRORS as e:
            note_error(_PROVIDER, f"{aws_account}/{region}", label, e)
    return infradata
