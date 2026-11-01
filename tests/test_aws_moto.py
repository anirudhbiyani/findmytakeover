"""End-to-end AWS collection against moto's in-process AWS: real boto3 calls,
real collector code, real diff. Covers what the contract tests can't: that
the collectors call the APIs in the right order and the results line up.

Skipped when moto isn't installed
(pip install "moto[apigateway,apigatewayv2,ec2,elb,elbv2,route53,s3,sts]").
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

moto = pytest.importorskip("moto")

import boto3  # noqa: E402

import findmytakeover  # noqa: E402
from collector import aws  # noqa: E402

ACCOUNT = "123456789012"  # moto's default account
REGION = "us-east-1"


@pytest.fixture
def mocked_aws(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # No CLI profiles, like a container: only the environment's credentials.
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setattr(aws, "_AMBIENT_ACCOUNTS", set())
    # Clients, sessions and credentials cached by an earlier test belong to
    # a different mock.
    monkeypatch.setattr(aws, "_CLIENTS", {})
    monkeypatch.setattr(aws, "_thread_local", aws.threading.local())
    aws._role_credentials.cache_clear()
    aws._home_region.cache_clear()
    # Every region times 14 services is slow under moto and adds nothing.
    monkeypatch.setattr(aws, "_regions", lambda account, iamrole: [REGION])
    with moto.mock_aws():
        yield


def _build_environment():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnets = [
        ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"{REGION}{az}")["Subnet"]["SubnetId"]
        for i, az in enumerate("ab")
    ]
    lb = boto3.client("elbv2", region_name=REGION).create_load_balancer(
        Name="web", Subnets=subnets, Scheme="internet-facing"
    )["LoadBalancers"][0]["DNSName"]
    eip = ec2.allocate_address(Domain="vpc")["PublicIp"]
    boto3.client("s3", region_name=REGION).create_bucket(Bucket="assets.example.com")

    route53 = boto3.client("route53")
    zone = route53.create_hosted_zone(Name="example.com", CallerReference="1")["HostedZone"]["Id"]

    def record(name, rtype, value=None, alias=None):
        rrset = {"Name": name, "Type": rtype}
        if alias:
            rrset["AliasTarget"] = {"HostedZoneId": "Z35SXDOTRQ7X7K", "DNSName": alias, "EvaluateTargetHealth": False}
        else:
            rrset.update(TTL=300, ResourceRecords=[{"Value": value}])
        return {"Action": "CREATE", "ResourceRecordSet": rrset}

    route53.change_resource_record_sets(HostedZoneId=zone, ChangeBatch={"Changes": [
        record("app.example.com", "CNAME", lb),
        record("alias.example.com", "A", alias=f"dualstack.{lb.upper()}."),
        record("ip.example.com", "A", eip),
        record("assets.example.com", "CNAME", "assets.example.com.s3-website-us-east-1.amazonaws.com"),
        record("old.example.com", "CNAME", "gone-1.us-east-1.elb.amazonaws.com"),
        record("released.example.com", "A", "3.3.3.3"),  # public, not ours
    ]})


def test_aws_scan_end_to_end(mocked_aws):
    _build_environment()
    providers = {"aws": {"enabled": True, "credentials": "findmytakeover-audit", "accounts": [ACCOUNT]}}

    result = findmytakeover.scan(providers, providers, verify_dns=False)

    found = {f["record"]: f for f in result["findings"]}
    # Live load balancer (plain and dualstack alias), Elastic IP and S3
    # website bucket all match inventory; only the two dead targets remain.
    assert set(found) == {"old.example.com", "released.example.com"}
    assert found["old.example.com"]["confidence"] == "inventory-miss"
    # The assumed-role path ran (moto's STS), with refreshable credentials.
    assert aws._role_credentials(ACCOUNT, "findmytakeover-audit").refresh_needed() is False


def test_default_credentials_without_profiles_scan_the_ambient_account(mocked_aws):
    """A container (IRSA, ECS task role, GitHub OIDC) has credentials but no
    ~/.aws profiles; credentials: default must still scan that account."""
    _build_environment()
    providers = {"aws": {"enabled": True, "credentials": "default", "accounts": []}}

    result = findmytakeover.scan(providers, providers, verify_dns=False)

    assert {f["record"] for f in result["findings"]} == {"old.example.com", "released.example.com"}
    assert {f["account"] for f in result["findings"]} == {ACCOUNT}
    # (moto lacks a few APIs, which show up as gaps; credentials aren't one.)
    assert not [e for e in result["collection_errors"] if "credentials" in e["what"]]


def test_s3_config_baseline_and_report(mocked_aws, tmp_path):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="scans")
    s3.put_object(Bucket="scans", Key="findmytakeover.config", Body=b"""
dns:
  aws: {enabled: true, credentials: default}
infra:
  aws: {enabled: true, credentials: default}
""")

    dns_config, infra_config, _ = findmytakeover.read_config("s3://scans/findmytakeover.config")
    assert dns_config["aws"]["credentials"] == "default"

    # First scheduled run: no baseline object yet.
    assert findmytakeover._load_baseline("s3://scans/findings.json") == []

    findings = [{"record": "a.example.com", "record_type": None, "target": "gone.github.io",
                 "target_owner": "External", "confidence": "high"}]
    findmytakeover._write_json_report("s3://scans/findings.json", findings, 0)
    assert findmytakeover._load_baseline("s3://scans/findings.json") == findings

    # A bucket that doesn't exist is an error, not an empty baseline.
    with pytest.raises(OSError):
        findmytakeover._read_text("s3://no-such-bucket/findings.json")
