#!/usr/bin/env python3
"""Self-check for dangling NS-delegation and Azure ALIAS detection.

Runs the real diff engine (findmytakeover._find_dangling_records) over synthetic
inventories — no cloud calls. Run: python3 test_dangling.py
"""

import pandas as pd

from collector import is_cloud_nameserver, zone_key
from findmytakeover import _find_dangling_records

RECORD_COLS = ["csp", "account", "dnskey", "dnsvalue"]
INFRA_COLS = ["csp", "account", "service", "value"]


def _dangling_values(records, infra):
    result = _find_dangling_records(
        pd.DataFrame(records, columns=RECORD_COLS),
        pd.DataFrame(infra, columns=INFRA_COLS),
        exclusions=set(),
    )
    return {result.loc[i, "dnsvalue"] for i in result.index if result.loc[i, "value"] == ""}


def test_helpers():
    assert is_cloud_nameserver("ns-1.awsdns-01.org")
    assert is_cloud_nameserver("ns1-01.AZURE-DNS.com")
    assert is_cloud_nameserver("ns-cloud-a1.googledomains.com")
    assert not is_cloud_nameserver("dana.ns.cloudflare.com")
    assert not is_cloud_nameserver("ns1.registrar.example")
    assert zone_key("Sub.Example.COM.") == "sub.example.com"


def test_dangling_ns_delegation():
    records = [
        # delegation whose child zone is gone → dangling
        ["aws", "111", "gone.example.com.", "gone.example.com"],
        # delegation whose child zone still exists (in some scanned account) → live
        ["aws", "111", "live.example.com.", "live.example.com"],
    ]
    infra = [["aws", "222", "hostedzone", "live.example.com"]]
    assert _dangling_values(records, infra) == {"gone.example.com"}


def test_azure_alias():
    gone_id = "/subscriptions/s/rg/providers/microsoft.network/publicipaddresses/gone"
    live_id = "/subscriptions/s/rg/providers/microsoft.network/publicipaddresses/live"
    records = [
        ["azure", "s", "gone.example.com", zone_key(gone_id)],
        ["azure", "s", "live.example.com", zone_key(live_id)],
    ]
    infra = [["azure", "s", "publicip", zone_key(live_id)]]
    assert _dangling_values(records, infra) == {zone_key(gone_id)}


if __name__ == "__main__":
    test_helpers()
    test_dangling_ns_delegation()
    test_azure_alias()
    print("ok")
