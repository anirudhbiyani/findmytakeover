# findmytakeover

findmytakeover detects dangling DNS record in a multi cloud environment. It does this by scanning all the DNS zones and the infrastructure present within the configured cloud service provider either in a single account or multiple accounts and finding the DNS record for which the infrastructure behind it does not exist anymore rather than using wordlist. It can easily detect and report potential subdomain takeovers that exist. 

AWS GovCloud and Azure Government are supported; see [Government clouds](#government-clouds).

![findmytakeover](findmytakeover.jpg "findmytakeover")

## Why?
They are a threat because they allow attackers to host infrastructure behind your domain which can be used for any sort of puropose and getting the entire traffic to an attacker-controlled domain with complete access to the domain’s content and resources.

This can become a breeding ground for malicious resources manipulated by an attacker that the domain owner has no control over. This means that the attacker can completely exercise dominance over the domain name to run an illegal service, launch phishing campaigns on unsuspecting victims and malign your organization’s good name in the market. 
 
## Installation

### From PyPI
```
pip install findmytakeover
findmytakeover --help
```

### With Docker
The image (Python 3.14 on Alpine) runs as a non-root user; config and cloud credentials are supplied at run
time via volume mounts:
```
docker build -t findmytakeover .
docker run --rm \
  -v "$PWD/findmytakeover.config:/app/findmytakeover.config" \
  -v "$HOME/.aws:/home/nonroot/.aws:ro" \
  findmytakeover
```

### From source
```
git clone https://github.com/anirudhbiyani/findmytakeover.git
cd findmytakeover/
pip3 install .
```

## Dependencies
Depending on the cloud provider, you would need permission read data. The following role would work for various cloud provider - 
  - Amazon Web Services - ViewOnlyRole and SecurityAudit
  - Microsoft Azure - Reader
  - Google Cloud - Viewer
  - Cloudflare - API token with Zone:Read, DNS:Read, Account:Read, Pages:Read
  - Oracle Cloud (OCI) - a group with `inspect`/`read` on dns, instances, load-balancers, and object-storage

## Usage
```
# findmytakeover --help
usage: findmytakeover [-h] [-c CONFIG_FILE] [-d DUMP_FILE]
                         [--verify-dns | --no-verify-dns] [--json JSON_FILE]
                         [--fail-on-findings] [--verify-http]
                         [--baseline JSON_FILE] [--fail-on-incomplete]
                         [--alert-webhook URL]
                         [--alert-confidence ALERT_CONFIDENCE]
                         [--json-format {findmytakeover,ocsf,defectdojo}]
                         [--security-hub] [--terraform-plan PLAN_JSON]
                         [--version]

Find dangling DNS records that may be vulnerable to subdomain takeover

options:
  -h, --help            show this help message and exit
  -c, --config-file CONFIG_FILE
                        Path to the configuration file
  -d, --dump-file DUMP_FILE
                        Path to save DNS and Infrastructure data
  --verify-dns, --no-verify-dns
                        Resolve third-party SaaS targets that match a known
                        takeover fingerprint, and third-party MX/SRV/SPF
                        targets, to confirm NXDOMAIN dangling records
                        (requires the dnspython package). Use --no-verify-dns
                        to disable network lookups entirely.
  --json JSON_FILE      Write findings as JSON to this path, for feeding a
                        SIEM, ticketing system or dashboard. Use '-' for
                        stdout.
  --fail-on-findings    Exit with status 1 when dangling records are found, so
                        a CI job or scheduled scan fails instead of passing
                        silently. Off by default so existing scripts keep
                        their exit codes.
  --verify-http         Fetch fingerprinted SaaS subdomains over HTTP(S) and
                        match the provider's 'no such site' page, confirming
                        takeovers that DNS can't (most SaaS providers wildcard
                        their DNS). Off by default: it sends requests to your
                        subdomains.
  --baseline JSON_FILE  A previous --json report. Findings are marked new or
                        already known, fixed ones are listed as resolved, and
                        --fail-on-findings only fails on new findings. A
                        missing file counts as an empty baseline (first run).
  --fail-on-incomplete  Exit with status 2 when part of the scan couldn't be
                        collected (a denied API, an unreachable account),
                        unless status 1 already applies.
  --alert-webhook URL   POST an alert to this webhook when there's something
                        to act on (repeatable). Slack incoming webhooks get a
                        Slack message; any other URL gets JSON. Prefer the
                        FINDMYTAKEOVER_ALERT_WEBHOOKS environment variable
                        (space-separated) so URLs stay out of process lists
                        and CI logs.
  --alert-confidence ALERT_CONFIDENCE
                        Comma-separated confidence levels that alert, or 'all'
                        (default: high,inventory-miss,target-nxdomain). With
                        --baseline only new findings alert.
  --json-format {findmytakeover,ocsf,defectdojo}
                        Format of the --json output: the native report
                        (default), OCSF 1.3 Detection Findings for SIEMs and
                        data lakes, or DefectDojo's generic findings import.
  --security-hub        Import findings into AWS Security Hub in the current
                        AWS session's account and region. With --baseline,
                        resolved findings are archived.
  --terraform-plan PLAN_JSON
                        Instead of scanning, check a plan from 'terraform show
                        -json': exit 1 if applying it would leave a DNS record
                        (in the plan, or live via the config's DNS providers
                        when the config exists) pointing at a resource it
                        destroys.
  --version             show program's version number and exit
```

### Third-party SaaS takeover detection

Beyond diffing DNS against cloud inventory, records pointing at a known
takeover-prone SaaS provider (GitHub Pages, Heroku, Shopify, Netlify,
WordPress.com, Discourse and about thirty others, kept in sync with
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)) are
fingerprinted, and the target hostname is resolved to confirm the finding.
**NXDOMAIN means the hostname is gone and likely claimable** — those are
reported as high confidence. A hostname that still resolves, or a lookup that
times out, is never treated as a confirmed finding by DNS alone. Providers that
verify domain ownership (Fastly, Zendesk, Statuspage, Unbounce, Desk) aren't
fingerprinted; a stale record pointing at one is still listed, as an
unclassified third-party target.

Disable network lookups entirely with `--no-verify-dns`.

**What NXDOMAIN can and can't tell you.** Most SaaS providers wildcard their
DNS, so every hostname under them resolves whether or not the resource exists —
including `github.io`, `herokuapp.com`, `myshopify.com` and `netlify.app`. Those
are reported as "fingerprinted, not confirmed dangling" and should be treated as
a worklist, not as noise.

**`--verify-http` settles them.** With it, each fingerprinted subdomain is
fetched over HTTPS (then HTTP) and the response is matched against the page the
provider serves for a hostname nobody has claimed ("There isn't a GitHub Pages
site here.", "No such app", ...). A match is reported as high confidence. It's
off by default because it sends requests to your subdomains; certificates aren't
verified (an unclaimed host serves the provider's certificate) and only the
first 256 KB of the body is read.

### Mail, SRV and SPF targets

MX and SRV targets and the domains an SPF policy `include:`s or `redirect=`s to
are checked too. A target in your cloud inventory is diffed like any other
record. A third-party target (Google, Microsoft, a mailing service) is resolved
and reported only if it returns NXDOMAIN — mail or SPF pointing at a name that
no longer exists, whose domain someone may be able to register. Everything
else is ignored, so the usual "MX points at Google" never shows up.

### Using it in CI

```
findmytakeover --json findings.json --fail-on-findings
```

`--fail-on-findings` makes the exit status 1 when anything is found, so a
pipeline fails instead of passing silently. The JSON report carries a summary
plus a `confidence` field per finding, so alerting can key on
`confidence == "high"`. Check `summary.complete` as well: when a collector
couldn't read something (a denied API, an unreachable account), it is `false`
and `collection_errors` says what's missing.

| Exit status | Meaning |
|---|---|
| `0` | Nothing to act on (or neither `--fail-on-*` flag given) |
| `1` | Findings, with `--fail-on-findings` — only *new* findings when `--baseline` is used |
| `2` | Part of the scan couldn't be collected, with `--fail-on-incomplete` (and no status 1) |

### Scheduled scanning and alerting

A daily scan only stays useful if it alerts on what *changed*. Pass the previous
run's report as `--baseline`:

```
findmytakeover --json findings.json --baseline previous/findings.json \
  --fail-on-findings --fail-on-incomplete
```

Each finding gets `"new": true|false`, findings that have disappeared are
listed under `resolved`, and `summary` gains `new` and `resolved` counts.
`--fail-on-findings` then fails only when something new appears. A missing
baseline file counts as empty (the first run); an unreadable one is an error,
so a broken baseline can't silently re-alert on everything. Findings are
matched on record, record type and target, so a confidence change alone isn't
"new". If the current scan is incomplete, some "resolved" findings may only be
unscanned — the console says so.

[`examples/github-actions-daily.yml`](examples/github-actions-daily.yml) is a
ready-to-copy GitHub Actions workflow for a repository that holds your config:

- runs daily, authenticating to AWS (and optionally Azure/GCP) with OIDC — no
  stored keys;
- uses the previous run's report as the baseline;
- opens a GitHub issue (label `dangling-dns`) per new finding and closes it
  when the finding disappears;
- keeps one "scan incomplete" issue open while permissions are missing;
- optionally sends [alerts](#alerts) to Slack or any webhook
  (`FINDMYTAKEOVER_ALERT_WEBHOOKS` secret);
- fails the run on new findings or an incomplete scan.

The scan needs your cloud credentials, so it belongs in your own repository,
not this one.

### Alerts

findmytakeover can post alerts itself. Give it one or more webhook URLs,
preferably through the environment so they stay out of process lists and CI
logs:

```
export FINDMYTAKEOVER_ALERT_WEBHOOKS="https://hooks.slack.com/services/T000/B000/XXXX"
findmytakeover --json findings.json --baseline previous/findings.json
```

(`--alert-webhook URL`, repeatable, works too.)

- **Slack** incoming webhooks (`hooks.slack.com`) get a readable message.
- **Any other URL** gets the alert as JSON — `findings`, `complete` and
  grouped `collection_errors` — for a Teams channel via a Power Automate
  "When a webhook request is received" flow, a SIEM, or your own handler.

What alerts:

- findings whose confidence is `high`, `inventory-miss` or `target-nxdomain`
  (change with `--alert-confidence`, or `--alert-confidence all`) — only the
  **new** ones when `--baseline` is used;
- an incomplete scan, even with no findings, because it quietly weakens every
  other result.

Nothing to act on means no message. A failed delivery prints a warning (with
the host only, never the URL) and doesn't change the exit status.

### Output

The console report groups findings by the cloud that owns the target, and splits
third-party targets into three tiers: confirmed unclaimed (high confidence),
fingerprinted but unconfirmed, and unclassified. Mail/SRV/SPF targets that don't
exist get their own section. Records pointing at private or internal addresses
are filtered out and reported only as a count.

If any part of the scan failed, the report ends with a warning listing what
couldn't be collected. Missing inventory turns live records into false
positives, and missing DNS data hides real findings, so an incomplete scan
should be fixed rather than trusted.

`--json` writes the same findings in a machine-readable form:

```json
{
  "tool": "findmytakeover",
  "version": "3.1.0",
  "summary": {
    "total": 12,
    "high_confidence": 2,
    "hidden_internal": 2,
    "by_target_owner": { "Amazon Web Services": 1, "External": 9 },
    "complete": true
  },
  "collection_errors": [],
  "findings": [
    {
      "record": "forum.example.com",
      "record_type": null,
      "target": "example.trydiscourse.com",
      "dns_provider": "Amazon Web Services",
      "account": "123456789012",
      "target_owner": "External",
      "saas_service": "Discourse",
      "dns_status": "nxdomain",
      "http_status": null,
      "confidence": "high"
    }
  ]
}
```

`record_type` is `MX`, `SRV` or `TXT` (an SPF include) for mail and service
targets, and `null` for A, AAAA, CNAME, alias and NS records. `http_status` is
`matched`, `no-match` or `unknown` when `--verify-http` fetched the subdomain.

`confidence` is one of `high` (fingerprinted SaaS target confirmed NXDOMAIN, or
serving the provider's unclaimed page), `inventory-miss` (a cloud resource that
no longer exists), `target-nxdomain` (a mail, SRV or SPF target that doesn't
exist), `fingerprinted-still-resolving`, `fingerprinted-dns-unknown`,
`fingerprinted-unverified`, or `unclassified-third-party`.

### Security tools: OCSF, DefectDojo, Security Hub

`--json-format` changes what `--json` writes:

- `ocsf` — an array of [OCSF](https://schema.ocsf.io/) 1.3 Detection Findings
  (class 2004), which Security Lake, Splunk, Sentinel, Datadog and most SIEMs
  ingest. The original finding is kept under `unmapped`.
- `defectdojo` — DefectDojo's *Generic Findings Import*, for vulnerability
  management with owners and SLAs.

`--security-hub` imports findings into AWS Security Hub (ASFF) in the current
AWS session's account and region (`AWS_REGION`); it needs
`securityhub:BatchImportFindings`. With `--baseline`, resolved findings are
archived.

Every format carries a stable finding id derived from the record, its type and
its target, so re-importing a daily scan updates findings instead of
duplicating them. Severity follows confidence: `high` → High;
`inventory-miss`, `target-nxdomain` → Medium; `fingerprinted-*` → Low;
`unclassified-third-party` → Info.

### Checking a Terraform plan

Most dangling records are created by deleting a resource and forgetting its DNS
record. `--terraform-plan` catches that before `apply`:

```
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
findmytakeover --terraform-plan plan.json
```

It exits 1 when a DNS record would point at a resource the plan destroys:
records in the plan itself (Route 53, Cloud DNS, Azure DNS, Cloudflare, OCI)
and, when a config file is present, live records from its DNS providers.
Records the plan deletes too, and resources it replaces at the same address,
are not reported. No cloud credentials are needed without a config file, so it
fits a pull-request check in Atlantis, Spacelift or GitHub Actions.

### As a Python library

```python
import findmytakeover

dns, infra, exclusions = findmytakeover.read_config("findmytakeover.config")
result = findmytakeover.scan(dns, infra, exclusions, verify_dns=True)
for finding in result["findings"]:
    print(finding["record"], finding["confidence"])
if result["collection_errors"]:
    print("incomplete scan")
```

`scan()` returns the same findings as `--json`, plus `collection_errors` and
`hidden_internal`.

## Configuration

The default configuration file is `findmytakeover.config` in the current
directory; override it with `-c`.

### Credentials

Each provider takes either explicit credentials or `credentials: default`, which
uses the session your local cloud CLI already has:

| Provider | `credentials: default` uses | Explicit alternative |
|---|---|---|
| AWS | the boto3 chain (`aws configure`, `aws sso login`, environment) | name of an IAM role to assume per account |
| Azure | `DefaultAzureCredential` (`az login`) | service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) |
| GCP | Application Default Credentials (`gcloud auth application-default login`) | path to a service-account key file |
| Cloudflare | `CLOUDFLARE_API_TOKEN` from the environment | the API token itself |
| Oracle | `~/.oci/config` | path to an OCI config file |

With `credentials: default` the `accounts` list becomes optional — AWS profiles,
Azure subscriptions, GCP projects, Cloudflare accounts and OCI compartments are
discovered automatically. Supply `accounts` to narrow the scan.

### Tuning

Providers, and their DNS and inventory sides, are collected at the same time.
Within a provider, every account, region (or subscription) and service is its
own task, run on a pool of `FINDMYTAKEOVER_MAX_WORKERS` threads (default `8`).
AWS calls back off adaptively when throttled, so raising the worker count
mostly costs retries rather than errors; lower it if collection errors mention
rate limits. The console prints how long each provider took.

API calls have connect/read timeouts and bounded retries, so a stalled
connection fails over instead of hanging. Assumed AWS roles refresh their
credentials, so scans longer than the role session (an hour by default) don't
fail halfway through.

An NXDOMAIN from the system resolver is checked against public resolvers
(`1.1.1.1`, `8.8.8.8`) before it becomes a finding: split-horizon DNS on a VPN
or corporate network can answer NXDOMAIN for a name that exists on the
internet. Set `FINDMYTAKEOVER_CONFIRM_RESOLVERS` to other resolvers
(comma-separated), or to an empty string to rely on the system resolver alone.
Public resolvers that can't be reached don't block a finding.

### Environment variables

All optional; the tool runs with none set.

| Variable | Default | What it does |
|---|---|---|
| `FINDMYTAKEOVER_MAX_WORKERS` | `8` | Threads per provider pool. Raise for slow scans; lower if errors mention throttling. |
| `FINDMYTAKEOVER_CONFIRM_RESOLVERS` | `1.1.1.1,8.8.8.8` | Public resolvers that can overrule an NXDOMAIN (comma-separated). Empty string disables the check. |
| `FINDMYTAKEOVER_ALERT_WEBHOOKS` | unset (no alerts) | Webhook URLs to alert, space-separated. Added to any `--alert-webhook`. |
| `CLOUDFLARE_API_TOKEN` | unset | Cloudflare token used with `credentials: default`. |
| `AWS_REGION` | unset | Region for `--security-hub` imports (or the profile's region). |

### Exclusions

`exclude.domains` entries are matched as DNS suffixes: `example.com` excludes
`example.com` and `a.example.com`, but not `notexample.com`. (Earlier releases
matched plain substrings.) `exclude.ipaddress` takes IPv4 and IPv6 CIDRs.

### Government clouds

**AWS GovCloud** needs no extra setting: give the profile (or the environment,
for role assumption) a GovCloud region such as `us-gov-west-1`. The partition
follows the region, so role ARNs become `arn:aws-us-gov:...`, and services
GovCloud doesn't offer (CloudFront, Global Accelerator) are skipped.

**Azure Government** is selected per provider block:

```
dns:
  azure:
    enabled: true
    credentials: default
    cloud: AzureUSGovernment    # default: AzureCloud
```

Every management client and credential then uses
`management.usgovcloudapi.net` and `login.microsoftonline.us`. Azure
Government DNS (`azuregov-dns.us`) and endpoint domains (`usgovcloudapi.net`,
`azurewebsites.us`, `azure.us` and so on) are recognised in every cloud.

### Example

```
exclude:
  ipaddress:
    - 100.1.0.0/16
  domains:
    - google.com 
    - example.com
    
dns:
  aws:
    enabled: false/true
    accounts:
      - 123456789012
      - 098765432109
      - 123123123123
    credentials: <Name of IAM Role that would be assumed>

  gcp:
    enabled: true/false
    credentials: <path to the service account's credentials file>
    accounts: 
      - project0
      - project1
      - project2

  azure:
    enabled: false/true
    credentials: <Service Account Key>
    accounts:
      - subscription1
      - subscription2
      - subscription3

  cloudflare:
    enabled: false/true
    credentials: default        # or the API token itself
    accounts:                   # optional: zone names to scope the scan
      - example.com

  oracle:
    enabled: false/true
    credentials: default        # or a path to an OCI config file
    accounts:                   # optional: compartment OCIDs
      - ocid1.compartment.oc1..example

infra:
  aws:
    enabled: false/true
    accounts:
      - 123456789012
      - 098765432109
      - 123123123123
    credentials: <Name of IAM Role that would be assumed>

  gcp:
    enabled: true/false
    credentials: <path to the service account's credentials file>
    accounts: 
      - project0
      - project1
      - project2

  azure:
    enabled: false/true
    credentials: <Service Account Key>
    accounts:
      - subscription1
      - subscription2
      - subscription3

  cloudflare:
    enabled: false/true
    credentials: default
    accounts:
      - example.com

  oracle:
    enabled: false/true
    credentials: default
    accounts:
      - ocid1.compartment.oc1..example
```

## Claude skill
A [Claude Code](https://docs.claude.com/en/docs/claude-code) skill is bundled under [`skills/dangling-dns-finder`](skills/dangling-dns-finder). It lets you run a dangling-DNS / subdomain-takeover audit conversationally ("find dangling domains across my AWS and GCP accounts") by driving `findmytakeover.py` itself — configuring providers, running the scan, interpreting the results, and showing (not running) the deletion commands. See its [SKILL.md](skills/dangling-dns-finder/SKILL.md) for usage.

This repo is also a Claude Code plugin marketplace, so the skill can be installed with `/plugin`:
```
/plugin marketplace add anirudhbiyani/findmytakeover
/plugin install findmytakeover@findmytakeover
```

## Limitations
This tool cannot guarantee 100% protection against subdomain takeovers.

- Dangling NS delegations are detected only when they point at a managed-DNS
  nameserver pool we inventory (AWS, Azure, GCP, Cloudflare, Oracle Cloud) —
  delegations to other DNS providers can't be judged from cloud inventory alone.
- Third-party SaaS targets can only be *confirmed* by DNS on providers that
  don't wildcard their DNS; the rest need `--verify-http`. See
  [Third-party SaaS takeover detection](#third-party-saas-takeover-detection).
- Records are matched to inventory after normalising case, trailing dots, the
  Route 53 `dualstack.` prefix, IPv6 spelling and S3 endpoint hostnames. A
  resource whose DNS name is still unrelated to anything its API returns can be
  reported even though it exists. Use `exclude` for known cases.
- A, AAAA, CNAME, NS, Azure ALIAS, MX, SRV and SPF (TXT) records are examined.
  An MX/SRV/SPF target that returns NXDOMAIN is reported, but whether its domain
  can actually be registered has to be checked by hand.
- AWS China, Azure China and other sovereign clouds beyond US Government aren't
  supported.

## Releasing

Bump `version` in `pyproject.toml` and merge to `main` to publish a GA release
to PyPI and a tagged GitHub release (wheel and sdist attached); open PRs
auto-publish `.dev` builds to TestPyPI. See
[PUBLISHING.md](PUBLISHING.md) for the flow and one-time trusted-publisher setup.

## Contributing

You can contribute to the project in many ways either by reporting bugs, writting documentation, or adding code.

Contributions are welcome! If you would like to contribute, please follow these steps:
  - Fork the repository.
  - Create a new branch:
    `$ git checkout -b feature/your-feature-name`
  - Make your changes and commit them:
    `$ git commit -m "Add your feature description"`
  - Push your changes to the forked repository:
    `$ git push origin feature/your-feature-name`
  - Open a pull request to the main repository.

have any questions? hit it me on GitHub or Email.
