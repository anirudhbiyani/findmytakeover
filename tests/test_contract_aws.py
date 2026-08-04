#!/usr/bin/env python3
"""Contract tests pinning the AWS API shapes collector/aws.py depends on.

These tests do NOT call AWS. They walk botocore's bundled service model —
the same JSON service definitions boto3 itself uses to build clients — and
assert that every operation and response field collector/aws.py reads still
exists with the shape we expect.

Why this file exists: a dependabot bump of boto3/botocore can ship an
updated service model where AWS renamed or restructured a response field.
Nothing in collector/aws.py would raise at import time — it would just
start silently returning fewer/no rows for that service (a `.get()` that
now always misses, or a KeyError swallowed by a broad except). Pinning the
shapes here makes that kind of drift fail CI loudly, at the field level,
instead of manifesting later as "detection went quiet".

No network calls, no AWS credentials: botocore.session.get_service_model()
only reads local JSON files bundled with the botocore package.

Run: python -m pytest tests/test_contract_aws.py -v
"""

import os
import sys

import pytest

# Make the repo root importable regardless of where the test is run from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import botocore.session

_session = botocore.session.get_session()

# Sentinel path element meaning "descend from a list shape into its element
# (member) shape" — mirrors the `[]` notation used in the task/collector
# comments, e.g. get_apis()["Items"][].ApiEndpoint -> ("Items", LIST, "ApiEndpoint").
LIST = "[]"


def _walk_shape(service, operation, shape, path):
    """Walk `path` from an operation's output shape, returning the final shape.

    Raises AssertionError with a message naming the service, operation, and
    exact point of failure the moment a step doesn't resolve — so a test
    failure tells you precisely which field botocore no longer has, not just
    that "a shape changed somewhere".
    """
    walked = []
    for step in path:
        walked.append(step)
        location = f"{service}.{operation} output" + "".join(
            f"[{s!r}]" if s != LIST else "[]" for s in walked
        )
        if step == LIST:
            assert shape is not None and shape.type_name == "list", (
                f"{location}: expected a list shape at this point, "
                f"got {getattr(shape, 'type_name', None)!r}. "
                f"The collector iterates this as a list — botocore's model "
                f"for {service}.{operation} no longer agrees."
            )
            shape = shape.member
        else:
            members = getattr(shape, "members", None)
            assert members is not None and step in members, (
                f"{location}: field {step!r} is missing from the "
                f"{service}.{operation} response shape in botocore's bundled "
                f"service model (available fields: "
                f"{sorted(members) if members is not None else 'n/a (not a structure shape)'}). "
                f"collector/aws.py reads this field — if botocore genuinely "
                f"dropped/renamed it, the collector is now silently broken "
                f"for this data point."
            )
            shape = members[step]
    return shape


def _assert_output_path(service, operation, *path):
    """Assert that `service.operation`'s response contains the given field path.

    `path` elements are either structure member names (str) or the LIST
    sentinel to descend into a list shape's element shape. Example:
        _assert_output_path("apigatewayv2", "GetApis", "Items", LIST, "ApiEndpoint")
    asserts get_apis()["Items"][].ApiEndpoint exists.
    """
    model = _session.get_service_model(service)
    operation_model = model.operation_model(operation)
    output_shape = operation_model.output_shape
    assert output_shape is not None, (
        f"{service}.{operation} has no output shape at all in botocore's "
        f"service model — the collector expects a response body."
    )
    _walk_shape(service, operation, output_shape, path)


# ---------------------------------------------------------------------------
# Route53 — DNS records + hosted zones (collector.aws._dns_for_account,
# collector.aws._collect_global_infra)
# ---------------------------------------------------------------------------

def test_route53_list_hosted_zones():
    _assert_output_path("route53", "ListHostedZones", "HostedZones", LIST, "Name")
    _assert_output_path("route53", "ListHostedZones", "HostedZones", LIST, "Id")
    _assert_output_path(
        "route53", "ListHostedZones", "HostedZones", LIST, "Config", "PrivateZone"
    )


def test_route53_list_resource_record_sets():
    _assert_output_path(
        "route53", "ListResourceRecordSets", "ResourceRecordSets", LIST, "Name"
    )
    _assert_output_path(
        "route53", "ListResourceRecordSets", "ResourceRecordSets", LIST, "Type"
    )
    _assert_output_path(
        "route53",
        "ListResourceRecordSets",
        "ResourceRecordSets",
        LIST,
        "ResourceRecords",
        LIST,
        "Value",
    )
    _assert_output_path(
        "route53",
        "ListResourceRecordSets",
        "ResourceRecordSets",
        LIST,
        "AliasTarget",
        "DNSName",
    )


# ---------------------------------------------------------------------------
# S3 / CloudFront / Global Accelerator — account-global resources
# (collector.aws._collect_global_infra)
# ---------------------------------------------------------------------------

def test_s3_list_buckets():
    _assert_output_path("s3", "ListBuckets", "Buckets", LIST, "Name")


def test_cloudfront_list_distributions():
    _assert_output_path(
        "cloudfront", "ListDistributions", "DistributionList", "Items", LIST, "DomainName"
    )


def test_globalaccelerator_list_accelerators():
    _assert_output_path(
        "globalaccelerator", "ListAccelerators", "Accelerators", LIST, "DnsName"
    )


# ---------------------------------------------------------------------------
# EC2 — regions + instance public network interfaces
# (collector.aws.infra, collector.aws._collect_region_infra)
# ---------------------------------------------------------------------------

def test_ec2_describe_regions():
    _assert_output_path("ec2", "DescribeRegions", "Regions", LIST, "RegionName")


def test_ec2_describe_instances():
    base = ("Reservations", LIST, "Instances", LIST, "NetworkInterfaces", LIST, "Association")
    _assert_output_path("ec2", "DescribeInstances", *base, "PublicIp")
    _assert_output_path("ec2", "DescribeInstances", *base, "PublicDnsName")


# ---------------------------------------------------------------------------
# ELB / ELBv2 — internet-facing load balancer DNS names
# ---------------------------------------------------------------------------

def test_elb_describe_load_balancers():
    _assert_output_path(
        "elb", "DescribeLoadBalancers", "LoadBalancerDescriptions", LIST, "Scheme"
    )
    _assert_output_path(
        "elb", "DescribeLoadBalancers", "LoadBalancerDescriptions", LIST, "DNSName"
    )


def test_elbv2_describe_load_balancers():
    _assert_output_path("elbv2", "DescribeLoadBalancers", "LoadBalancers", LIST, "Scheme")
    _assert_output_path("elbv2", "DescribeLoadBalancers", "LoadBalancers", LIST, "DNSName")


# ---------------------------------------------------------------------------
# Elastic Beanstalk — application environments
# ---------------------------------------------------------------------------

def test_elasticbeanstalk_describe_applications():
    _assert_output_path(
        "elasticbeanstalk", "DescribeApplications", "Applications", LIST, "ApplicationName"
    )


def test_elasticbeanstalk_describe_environments():
    _assert_output_path(
        "elasticbeanstalk", "DescribeEnvironments", "Environments", LIST, "EndpointURL"
    )
    _assert_output_path(
        "elasticbeanstalk", "DescribeEnvironments", "Environments", LIST, "CNAME"
    )


# ---------------------------------------------------------------------------
# RDS — instance endpoints
# ---------------------------------------------------------------------------

def test_rds_describe_db_instances():
    _assert_output_path(
        "rds", "DescribeDBInstances", "DBInstances", LIST, "Endpoint", "Address"
    )


# ---------------------------------------------------------------------------
# OpenSearch — domain names + endpoints
# ---------------------------------------------------------------------------

def test_opensearch_list_domain_names():
    _assert_output_path(
        "opensearch", "ListDomainNames", "DomainNames", LIST, "DomainName"
    )


def test_opensearch_describe_domain():
    _assert_output_path("opensearch", "DescribeDomain", "DomainStatus", "Endpoint")


# ---------------------------------------------------------------------------
# API Gateway v2 — manual NextToken pagination + endpoint
# ---------------------------------------------------------------------------

def test_apigatewayv2_get_apis():
    _assert_output_path("apigatewayv2", "GetApis", "Items", LIST, "ApiEndpoint")
    # Manual NextToken pagination (no boto3 paginator for GetApis) — the
    # collector loops on this field itself, so it must keep existing.
    _assert_output_path("apigatewayv2", "GetApis", "NextToken")


# ---------------------------------------------------------------------------
# Lambda — function URLs
# ---------------------------------------------------------------------------

def test_lambda_list_functions():
    _assert_output_path("lambda", "ListFunctions", "Functions", LIST, "FunctionName")


def test_lambda_get_function_url_config():
    _assert_output_path("lambda", "GetFunctionUrlConfig", "FunctionUrl")


# ---------------------------------------------------------------------------
# EKS — cluster endpoints
# ---------------------------------------------------------------------------

def test_eks_list_clusters():
    # clusters is a bare list of cluster-name strings, not a list of
    # structures — assert the element shape is still a scalar string so the
    # collector can pass cluster_name straight into describe_cluster(name=...).
    model = _session.get_service_model("eks")
    clusters_shape = model.operation_model("ListClusters").output_shape.members["clusters"]
    assert clusters_shape.type_name == "list", (
        "eks.ListClusters output field 'clusters' is no longer a list shape "
        f"(got {clusters_shape.type_name!r}) — collector.aws iterates it directly."
    )
    element_shape = clusters_shape.member
    assert element_shape.type_name == "string", (
        "eks.ListClusters 'clusters' elements are no longer plain strings "
        f"(got {element_shape.type_name!r}) — collector.aws passes each "
        "element straight to describe_cluster(name=...)."
    )


def test_eks_describe_cluster():
    _assert_output_path("eks", "DescribeCluster", "cluster", "endpoint")


# ---------------------------------------------------------------------------
# ECR — repository registry endpoints
# ---------------------------------------------------------------------------

def test_ecr_describe_repositories():
    _assert_output_path(
        "ecr", "DescribeRepositories", "repositories", LIST, "repositoryUri"
    )


# ---------------------------------------------------------------------------
# Amplify — app default domains
# ---------------------------------------------------------------------------

def test_amplify_list_apps():
    _assert_output_path("amplify", "ListApps", "apps", LIST, "defaultDomain")


# ---------------------------------------------------------------------------
# App Runner — service URLs
# ---------------------------------------------------------------------------

def test_apprunner_list_services():
    _assert_output_path(
        "apprunner", "ListServices", "ServiceSummaryList", LIST, "ServiceUrl"
    )


# ---------------------------------------------------------------------------
# STS — temporary credentials from assume_role (collector.aws._assume_role,
# collector.aws._create_client)
# ---------------------------------------------------------------------------

def test_sts_assume_role():
    _assert_output_path("sts", "AssumeRole", "Credentials", "AccessKeyId")
    _assert_output_path("sts", "AssumeRole", "Credentials", "SecretAccessKey")
    _assert_output_path("sts", "AssumeRole", "Credentials", "SessionToken")


# ---------------------------------------------------------------------------
# Negative controls — prove the test machinery can actually fail, so a bug
# in _assert_output_path/_walk_shape (e.g. accidentally returning True for
# anything) can't make this whole file pass vacuously.
# ---------------------------------------------------------------------------

def test_negative_control_bogus_field_is_absent():
    model = _session.get_service_model("route53")
    hosted_zone_shape = (
        model.operation_model("ListHostedZones").output_shape.members["HostedZones"].member
    )
    assert "TotallyBogusFieldThatWillNeverExist" not in hosted_zone_shape.members


def test_negative_control_assert_output_path_raises_on_bogus_field():
    with pytest.raises(AssertionError):
        _assert_output_path(
            "route53", "ListHostedZones", "HostedZones", LIST, "TotallyBogusFieldThatWillNeverExist"
        )


def test_negative_control_assert_output_path_raises_on_bogus_operation():
    with pytest.raises(Exception):
        _assert_output_path("route53", "ThisOperationDoesNotExist")


if __name__ == "__main__":
    test_route53_list_hosted_zones()
    test_route53_list_resource_record_sets()
    test_s3_list_buckets()
    test_cloudfront_list_distributions()
    test_globalaccelerator_list_accelerators()
    test_ec2_describe_regions()
    test_ec2_describe_instances()
    test_elb_describe_load_balancers()
    test_elbv2_describe_load_balancers()
    test_elasticbeanstalk_describe_applications()
    test_elasticbeanstalk_describe_environments()
    test_rds_describe_db_instances()
    test_opensearch_list_domain_names()
    test_opensearch_describe_domain()
    test_apigatewayv2_get_apis()
    test_lambda_list_functions()
    test_lambda_get_function_url_config()
    test_eks_list_clusters()
    test_eks_describe_cluster()
    test_ecr_describe_repositories()
    test_amplify_list_apps()
    test_apprunner_list_services()
    test_sts_assume_role()
    test_negative_control_bogus_field_is_absent()
    print("ok")
