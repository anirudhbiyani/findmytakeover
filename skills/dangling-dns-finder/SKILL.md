---
name: dangling-dns-finder
description: >-
  Detect dangling DNS records and subdomain-takeover risks across a multi-cloud
  environment by running the findmytakeover tool. Use whenever the user wants
  to find dangling domains/records, stale CNAMEs, subdomain takeover exposure,
  orphaned DNS entries, or audit their DNS zones for records pointing at
  deleted cloud resources — dead load balancers, released public IPs, deleted
  S3 buckets/CloudFront/App Service, or expired SaaS targets (GitHub Pages,
  Heroku, Shopify...). Triggers on "dangling domains", "dangling DNS",
  "subdomain takeover", "audit my DNS", "find stale/orphaned DNS records",
  "dead CNAMEs", "broken MX/SPF", asking what's safe to delete, or setting up a
  daily/CI scan with alerts. Covers AWS (incl. GovCloud), Azure (incl. Azure
  Government), GCP, Cloudflare and Oracle Cloud, using read-only access the
  user already has.
---

# Dangling DNS Finder

Find DNS records that point at infrastructure that no longer exists — the
classic subdomain-takeover setup. A `CNAME` to a deleted ELB or S3 bucket, or
an `A` record to a released cloud IP, can be reclaimed by someone else and
used to serve content under the user's domain.

This skill drives the `findmytakeover` tool. It enumerates every DNS record
**and** every live infrastructure endpoint across the configured accounts,
then reports records whose target is in **none** of them. Third-party SaaS
targets are checked for NXDOMAIN (and optionally an "unclaimed site" page).
No wordlists, no guessing.

Do **not** write your own scripts to enumerate DNS or probe endpoints — the
tool collects both sides and diffs them. Your job is to configure it, run it,
and interpret the JSON. The one exception is re-checking a single record with
`dig` right before remediation (step 5).

## Prerequisites

- **The tool.** Use whichever is available, in this order:
  - `findmytakeover --version` already works → use it.
  - Inside a checkout of the repo → `pip install .` (Python 3.12+).
  - Otherwise → `pipx install findmytakeover`, or the Docker image (mount the
    config and cloud credential directories read-only).
  Below, `findmytakeover` means whichever of these you ended up with.
- **Read-only credentials** already working in the local CLIs. The tool never
  logs in for the user:
  - **AWS** — `ViewOnlyAccess` + `SecurityAudit` (or an assumable read-only role)
  - **GCP** — `Viewer` (Application Default Credentials, or a service-account key)
  - **Azure** — `Reader` (`az login`, or tenant/client/secret)
  - **Cloudflare** — read-only API token (`CLOUDFLARE_API_TOKEN`)
  - **Oracle (OCI)** — `read`/`inspect` (`~/.oci/config` DEFAULT profile)

## Workflow

### 1. Configure

The tool reads a YAML config (`findmytakeover.config` in the repo is the
annotated example; pass another with `-c`). Enable only the providers the user
has. For each, set `enabled: true` and pick credentials:

- `credentials: default` — the local CLI's session, with accounts / projects /
  subscriptions auto-discovered. Simplest; prefer it.
- Otherwise an IAM role name (AWS), a service-account JSON path (GCP), or a
  tenant/client/secret mapping (Azure), with `accounts:` listed explicitly.

Each provider appears under both `dns:` and `infra:`. A record can only be
judged against inventory that was collected, so enable `infra` for **every**
provider that could own a target, not just the one hosting the zone.

Government clouds:
- **AWS GovCloud** — no setting; the partition comes from the profile's region
  (`us-gov-west-1` / `us-gov-east-1`).
- **Azure Government** — add `cloud: AzureUSGovernment` to the Azure block.

`exclude:` takes IP ranges (CIDR, v4/v6) and domains. A domain matches itself
and its subdomains, not substrings.

Confirm the scope (providers, accounts, exclusions) with the user before
running — wrong account scope is the main source of false positives. When
showing the config, never echo client secrets, tokens or key paths back.

### 2. Run

```bash
findmytakeover -c findmytakeover.config --json findings.json
```

- Read `findings.json`, not the console. Each finding has `record`,
  `record_type`, `target`, `dns_provider`, `account`, `target_owner`,
  `saas_service`, `dns_status`, `http_status` and `confidence`.
- `-d dump.csv` saves the raw DNS + inventory that was diffed. Use it when a
  known-good record shows up.
- `--verify-http` fetches fingerprinted SaaS subdomains to match the
  provider's "no such site" page. It sends requests to the user's hosts, so
  **ask first**. It confirms takeovers DNS alone can't (most SaaS wildcard DNS).
- `--no-verify-dns` makes no lookups at all, for offline or locked-down runs.

### 3. Check completeness first

If `summary.complete` is `false` (console: "WARNING: the scan is incomplete"),
some DNS or inventory was not read. `collection_errors` names the provider,
scope and API that failed — usually a missing permission. A missing inventory
makes live records look dangling, so report the gaps **before** the findings
and offer to fix and rerun.

### 4. Report

Rank by `confidence`, highest first:

| confidence | Meaning | Treat as |
|---|---|---|
| `high` | SaaS target is NXDOMAIN, or serves the provider's unclaimed-site page | Likely claimable now — urgent |
| `inventory-miss` | Cloud-looking target not in any scanned account | Dangling, unless an unscanned account owns it |
| `target-nxdomain` | MX / SRV / SPF target doesn't exist | Broken mail/SPF; a takeover only if that domain is registrable (check WHOIS) |
| `fingerprinted-still-resolving` / `-dns-unknown` / `-unverified` | Known takeover-prone SaaS, not confirmed | Review; suggest `--verify-http` |
| `unclassified-third-party` | Points outside every known cloud/SaaS | Low; ask the user who owns it |

Present a table per tier: **Record · Type · Target · Confidence · DNS
provider · Account**. Call out customer-named and `*-prod` hosts for manual
confirmation.

### 5. Remediate (show, don't run)

The tool only reports. For each confirmed record:

1. Re-check it now (`dig +short <record> <type>` and, for a CNAME, the
   target) — it may have been fixed or re-pointed since the scan.
2. Show the deletion for the DNS provider: `aws route53
   change-resource-record-sets` (DELETE change batch), `gcloud dns record-sets
   delete`, `az network dns record-set <type> delete`, Cloudflare `DELETE
   /zones/{zone_id}/dns_records/{id}`, or `oci dns record rrset delete`.

DNS deletion is outward-facing and hard to reverse — show the command and let
the user run it. Only run it yourself when explicitly told to, and never
batch-delete customer-named or `*-prod` records without confirming each one.
Never delete an apex MX without asking where mail should go instead.

### 6. Make it recurring (if asked)

- `--baseline previous.json` marks each finding `new: true/false` and adds
  `new` / `resolved` to the report; with a baseline, `--fail-on-findings`
  fails only on new findings. A missing baseline file is treated as empty.
- `--fail-on-incomplete` exits 2 when the scan had gaps. With both flags,
  failing findings take precedence (exit 1).
- `--alert-webhook URL` (repeatable) or `FINDMYTAKEOVER_ALERT_WEBHOOKS`
  (comma-separated) posts new findings at `--alert-confidence` levels. Slack
  URLs get Slack formatting, anything else gets JSON. Keep webhook URLs in
  secrets — never in the config or the repo.
- `examples/github-actions-daily.yml` wires all of this into a daily GitHub
  Actions job with OIDC cloud auth, the previous report as baseline, and one
  GitHub issue per finding. Copy it rather than writing a workflow from
  scratch.

## Not a takeover risk

Bucket these as "stale / out of scope", not takeover risks:

- **Cert validation** — `*.acm-validations.aws`,
  `*.authorize.certificatemanager.goog`, `_acme-challenge.*`.
- **Email auth (DKIM etc.)** — CNAMEs into live SaaS zones (`*.domainkey.*`,
  `*.dkim.*`, `*.hubspotemail.net`, ...). Expected to have no inventory in the
  user's accounts.
- **SOA / apex NS** — out of scope; never delete as part of this.
- **Private / internal records** — records named under `.internal`, `.local`
  or cluster DNS, or pointing at private/reserved IPs, are filtered out
  (counted, not reported).
- **Resources in an account that wasn't scanned** — the #1 false positive.
  Widen the scan, or add the range/domain to `exclude:` once the user confirms
  ownership.

## Pitfalls

- **Matching already normalises** trailing dots, case, Route 53 `dualstack.`
  aliases, IPv6 forms and S3 endpoint hostnames (to the bucket name). If a
  known-good record still shows up, compare its value with the dump before
  assuming a bug.
- **NS delegations** are checked only when they point at a cloud nameserver
  pool (Route 53, Azure / Azure Gov, Google, Cloudflare, OCI). The child zone
  is proven live from the **infra** side, so the provider hosting it must have
  `infra` enabled.
- **A permissions error is a credentials problem**, not a tool bug: name the
  missing permission from `collection_errors` and stop there.
