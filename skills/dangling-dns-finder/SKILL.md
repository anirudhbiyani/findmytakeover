---
name: dangling-dns-finder
description: >-
  Detect dangling DNS records and subdomain-takeover risks across a multi-cloud
  environment by running the bundled findmytakeover tool. Use whenever the user
  wants to find dangling domains/records, stale CNAMEs, subdomain takeover
  exposure, orphaned DNS entries, or audit their DNS zones for records pointing
  at deleted cloud resources — dead load balancers (ELBs), released
  EC2/GCP/Azure IPs, or expired SaaS targets. Triggers on "dangling domains",
  "dangling DNS", "subdomain takeover", "audit my DNS", "find stale/orphaned DNS
  records", "dead CNAMEs", or asking what's safe to delete. Works across AWS,
  GCP, and Azure using the accounts the user can already read.
---

# Dangling DNS Finder

Find DNS records that point at infrastructure that no longer exists — the
classic subdomain-takeover setup. A `CNAME` to a deleted ELB, or an `A` record
to a released cloud IP, can be silently reclaimed by someone else and used to
serve content under your domain.

This skill drives the repo's own tool, [`findmytakeover.py`](../../findmytakeover.py).
It enumerates every DNS record **and** every live infrastructure endpoint
(IPs, ELB/LB hostnames, etc.) across the configured AWS/GCP/Azure accounts,
then reports any DNS record whose value has **no** matching live resource. No
wordlists, no guessing — a record is dangling because the thing it points at is
not in your inventory.

Do **not** write new scripts to resolve DNS or probe endpoints — the tool
already collects both sides and diffs them. Your job is to configure it, run
it, and interpret the output.

## Prerequisites

- Read-only cloud credentials for the accounts being scanned, already set up in
  the local CLIs:
  - **AWS** — `ViewOnlyAccess` + `SecurityAudit` (or an assumable IAM role)
  - **GCP** — `Viewer` (Application Default Credentials, or a service-account key)
  - **Azure** — `Reader` (Azure CLI login, or tenant/client/secret)
  - **Cloudflare** — read-only API token (`CLOUDFLARE_API_TOKEN` env, or a token string)
  - **Oracle (OCI)** — `read`/`inspect` group (`~/.oci/config` DEFAULT profile, or a config path)
- Dependencies: `pip3 install .` from the repo root (installs from `pyproject.toml`).

## Workflow

### 1. Configure

The tool reads [`findmytakeover.config`](../../findmytakeover.config) (YAML) —
default path is the repo root, override with `-c`. Enable only the providers the
user actually has. For each, set `enabled: true` and pick credentials:

- `credentials: default` — use the local CLI's logged-in creds and auto-discover
  accounts/projects/subscriptions. Simplest; prefer this.
- Otherwise an IAM role name (AWS), a service-account JSON path (GCP), or a
  tenant/client/secret mapping (Azure) — and list `accounts:` explicitly.

A provider appears under both `dns:` and `infra:` — both must be enabled for the
dangling check to run (it needs both sides to diff). Use `exclude:` for IP
ranges/domains that are known-safe and should never be flagged (e.g. SaaS email
domains, reserved ranges).

Confirm the config with the user before running — wrong account scope is the
main way this wastes time.

### 2. Run

```bash
python3 findmytakeover.py -c findmytakeover.config
# add -d dump.csv to also save the raw DNS + infrastructure inventory
```

It prints how many DNS records and infra resources it collected per provider,
then one line per dangling record:

```
Found dangling DNS record - <name> with value <value> in <cloud> cloud (account/...: <id>)
```

Use `-d <file>` whenever the user wants to inspect the raw data or when a result
looks surprising — the dump shows exactly what DNS and infra were compared.

### 3. Report

Present the dangling records as a table: **Subdomain · Value (target) · Cloud ·
Account**. Group by cloud. Call out anything sensitive (customer-named
subdomains, `*-prod` hosts) for manual confirmation before any deletion.

Frame confidence honestly (see Interpreting results) — a value missing from the
inventory is a strong signal, not proof, and some classes of record are expected
to have no backing infra.

### 4. Remediate (show, don't run)

The tool only reports; it does not delete. For each confirmed dangling record,
show the user the deletion command for their DNS provider (e.g.
`aws route53 change-resource-record-sets` with a change batch, `gcloud dns
record-sets delete`, `az network dns record-set ... delete`).

DNS deletion is hard to reverse and outward-facing — default to **showing** the
command and letting the user run it. Only run it yourself if they explicitly say
so, and never batch-delete customer-named or `*-prod` records without a
record-by-record confirmation.

## Interpreting results — what is NOT a takeover risk

A record can have no matching infra yet be perfectly fine. Bucket these
separately as "stale / out of scope," not as takeover risks:

- **Cert validation** — `*.acm-validations.aws`, `*.authorize.certificatemanager.goog`,
  `_acme-challenge.*`. These point at validation zones / single-use tokens, not
  service endpoints. Not a takeover vector.
- **Email auth (DKIM/SPF etc.)** — CNAMEs into live SaaS provider zones
  (`*.dkim.*`, `*.domainkey.*`, `*.hubspotemail.net`, salesforce/highspot/etc.).
  Expected to have no infra in *your* accounts.
- **MX / TXT / SOA / apex NS** — out of scope; never delete as part of this.
  (Child NS *delegations* to a cloud NS pool are checked — see Pitfalls.)
- **Resources in an account you didn't scan.** If a value points at real infra
  living in an account/project/subscription that wasn't in the config, it shows
  up as dangling but isn't. Widen the scan before trusting the result — this is
  the #1 false positive. Add such ranges/domains to `exclude:` once confirmed.

A genuine takeover risk is a record pointing at a real endpoint (ELB, cloud
host, app) that exists in **none** of the accounts you scanned.

## Pitfalls

- **Incomplete account scope = false positives.** The tool can only match against
  infra in the accounts it can read. A value owned by an unscanned account looks
  dangling. Always confirm the config covers every account that could own the
  targets before reporting.
- **Both `dns` and `infra` must be enabled** (and for the same providers you care
  about) or there's nothing to diff — the tool will say so and exit.
- **Credentials must already work in the CLI.** The tool assumes roles / uses ADC
  / Azure login; it does not log you in. A permissions error means fix the cloud
  creds, not the tool.
- **NS dangling is partially covered** — the tool flags child NS delegations
  that point at a cloud-provider nameserver pool (awsdns/azure-dns/googledomains)
  but whose delegated zone no longer exists in any scanned account. Delegations
  to other DNS providers are out of scope (can't be judged from cloud inventory).
  The delegated zone is proven "live" from the **infra** side (zone-name rows),
  so the provider hosting the child zone must have `infra` enabled and scanned —
  otherwise a live delegation looks dangling.
- **Matching is on the record value.** A CNAME/A whose value exactly matches a
  collected infra endpoint is considered live; partial/normalized mismatches
  (trailing dots, case) are worth spot-checking with `-d` if a known-good record
  shows up as dangling.
