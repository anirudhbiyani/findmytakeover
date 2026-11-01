# Changelog

All notable changes to findmytakeover are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for 1.x predate this file and were reconstructed from git history, so
they summarise the shape of each release rather than listing every commit.

## [Unreleased]

### Added

- **`--baseline FILE`** compares a scan with a previous `--json` report: each
  finding is marked `new`, disappeared findings are listed under `resolved`,
  and `--fail-on-findings` fails only on new findings.
- **Built-in alerting**: `--alert-webhook URL` or the
  `FINDMYTAKEOVER_ALERT_WEBHOOKS` environment variable. Slack incoming webhooks
  get a Slack message; other URLs get JSON. Alerts on actionable findings
  (`high`, `inventory-miss`, `target-nxdomain` by default, tunable with
  `--alert-confidence`) — only new ones with `--baseline` — and on an
  incomplete scan. Webhook URLs are never printed.
- **`--fail-on-incomplete`** exits with status 2 when part of the scan couldn't
  be collected (status 1 for findings still takes precedence).
- **`examples/github-actions-daily.yml`**: a daily scheduled scan with OIDC
  cloud credentials, the previous run as baseline, a GitHub issue per new
  finding (closed when it's resolved), a standing "scan incomplete" issue, and
  optional webhook alerts.
- **`--json-format ocsf|defectdojo`**: OCSF 1.3 Detection Findings for SIEMs
  and Security Lake, or DefectDojo's generic findings import. Findings carry a
  stable id, so re-imports update instead of duplicating.
- **`--security-hub`** imports findings into AWS Security Hub (ASFF), archiving
  resolved ones when `--baseline` is used.
- **`--terraform-plan PLAN_JSON`** fails a plan that would leave a DNS record
  pointing at a resource it destroys — records in the plan, plus live DNS when
  a config is present.
- **`findmytakeover.scan()`** as a library entry point, returning the same
  findings as `--json`.

### Changed

- Console findings print record names without the trailing dot.

## [3.0.0] — 2026-10-31

### Changed

- Docker image moved from distroless (Debian 13 / Python 3.13) to
  `python:3.14-alpine`. Still runs as non-root uid 65532 with
  `HOME=/home/nonroot`, so existing credential mounts are unchanged.

### Added

- **AWS GovCloud and Azure Government.** AWS derives the partition from the
  profile's region (role ARNs, STS endpoint, skipping CloudFront and Global
  Accelerator where they don't exist). Azure takes `cloud: AzureUSGovernment`
  and points every client and credential at the Government endpoints. Azure
  Government DNS and endpoint domains are recognised as Azure.
- **MX, SRV and SPF records.** Their targets are diffed against inventory; a
  third-party target is reported only when it returns NXDOMAIN
  (`confidence: target-nxdomain`).
- **`--verify-http`** (opt-in) confirms wildcard-DNS SaaS takeovers by matching
  the provider's "no such site" page.
- **More AWS inventory**: every Elastic IP and every public IPv4/IPv6 on any
  network interface (NAT gateways, NLBs, ECS tasks, ...), API Gateway REST APIs
  and custom domain targets (v1 and v2), and Cognito hosted-UI domains.
- **Incomplete-scan reporting.** A failed API call is recorded instead of
  aborting or being swallowed; the console ends with a warning and the JSON
  report gains `summary.complete` and `collection_errors`.
- SaaS fingerprints synced with can-i-take-over-xyz (17 services added).

### Changed

- **Python 3.12 or newer is required** (was 3.11). CI tests 3.12, 3.14 and 3.15.
- `exclude.domains` matches DNS suffixes instead of substrings.
- Fastly, Zendesk, Statuspage, Unbounce and Desk are no longer fingerprinted:
  they verify domain ownership, so they were never claimable.
- `--dump-file` overwrites instead of appending to earlier runs.
- JSON findings gain `record_type` and `http_status`.

### Fixed

- Match cloud targets and nameservers by DNS suffix boundaries, preventing
  provider-looking substrings in unrelated hostnames from being classified as
  cloud infrastructure.
- Route 53 alias records (`dualstack.` prefix, trailing dot, mixed case) never
  matched the live ELB or CloudFront they point at, so every alias was reported
  as dangling.
- Records pointing at S3 endpoints never matched the bucket inventory; S3
  hostnames (including website and dual-stack endpoints) now reduce to the
  bucket name.
- One denied or failing AWS API call aborted collection for the whole run; each
  service now fails on its own. Any provider failing outright no longer takes
  the others down with it.
- An empty config file crashed with a `TypeError`.
- The README pointed at a `demo/` directory that doesn't exist.

## [2.0.0] — 2026-08-04

Everything in this release landed in 2026. It roughly triples the tool's
provider and resource coverage, adds a second detection technique beyond
inventory diffing, and turns the project into something installable,
containerised and CI-gateable.

### Added

**New providers**
- **Cloudflare** as both a DNS and an infrastructure provider.
- **Oracle Cloud Infrastructure (OCI)** as both a DNS and an infrastructure
  provider, scanning every subscribed region.

**New detection capabilities**
- **Dangling NS delegation detection.** A child zone delegated to a managed-DNS
  nameserver pool that no longer holds the zone is reported as dangling.
  Covers the AWS, Azure, GCP, Cloudflare and OCI pools.
- **Azure ALIAS record resolution**, matching records that point at an Azure
  resource id (Traffic Manager, Public IP, CDN, Front Door) against live
  resource ids.
- **Third-party SaaS takeover fingerprinting**, confirmed by a passive DNS
  resolution check. Targets matching a known takeover-prone SaaS suffix
  (GitHub Pages, Heroku, Shopify, Netlify, Fastly, Zendesk and others) are
  resolved; **NXDOMAIN** marks a high-confidence, likely-claimable finding. A
  hostname that still resolves — or a lookup that times out — is never reported
  as confirmed. DNS only: no HTTP requests are made. Opt out with
  `--no-verify-dns`.
- **Noise suppression**: records pointing at private, reserved or internal
  addresses (`.local`, `.internal`, cluster DNS) are filtered out of findings,
  and remaining findings are grouped by the cloud that owns the target.

**Authentication**
- `credentials: default` uses the local cloud CLI session instead of
  credentials embedded in the config — the boto3 default chain
  (`aws configure` / `aws sso login`), `DefaultAzureCredential` (`az login`),
  Application Default Credentials (`gcloud`), `~/.oci/config`, and
  `CLOUDFLARE_API_TOKEN`.
- **Account auto-discovery** when using local CLI credentials: AWS profiles,
  GCP projects, Azure subscriptions, Cloudflare accounts and OCI compartments
  are enumerated automatically, so `accounts` becomes optional.

**Expanded infrastructure coverage** — now **63 enumerated resource types**
across five providers:
- AWS (16): added Lambda function URLs, EKS, ECR, Global Accelerator, Amplify
  and App Runner.
- GCP (10): added Cloud Run, App Engine, GKE, Artifact Registry and Cloud SQL.
- Azure (20): added Virtual Machines and VM Scale Sets (previously not
  collected at all), Load Balancer, Application Gateway, AKS, Container Apps
  and Cosmos DB, plus public-IP **FQDNs** in addition to raw addresses.
- Cloudflare (8): Workers, R2, custom hostnames, load balancers, Spectrum and
  Tunnels, alongside zones and Pages.
- OCI (9): added Autonomous Database and DB Systems, API Gateway, Functions,
  Network Load Balancer and Container Instances.

**Output and exit behaviour**
- `--json PATH` (or `-` for stdout) writes structured findings plus a summary,
  each finding carrying a `confidence` field, for feeding a SIEM, ticketing
  system or dashboard.
- `--fail-on-findings` exits `1` when dangling records are found so a scheduled
  scan or CI job fails instead of passing silently. Opt-in; the default exit
  code is unchanged.
- `--version`.

**Packaging and distribution**
- `pyproject.toml` with a `findmytakeover` console entry point, making the tool
  `pip install`-able.
- Distroless multi-stage **Docker image** (Debian 13 / Python 3.13); config and
  cloud credentials are supplied at run time via volume mounts.
- Tag-free publishing: a push to `main` releases that version to PyPI, and a
  pull request publishes a `.devN` pre-release to TestPyPI.

**CI**
- Docker workflow building the image and smoke-testing that the entrypoint runs
  and every collector imports inside the container.
- Test and lint workflow: installs the package the way a user would, asserts
  every collector imports on Python 3.11 / 3.13 / 3.14, runs the test suite,
  and lints with ruff's pyflakes rules.

**Tests** — the suite went from a single self-check script to **94 tests**,
including SDK **contract tests** for all five providers. These pin every API
field path the collectors read against each SDK's own shipped schema (AWS's
service model inside botocore, proto-plus message fields, Azure model
instances, Cloudflare accessors, OCI `swagger_types`), so a dependency bump
that renames or removes a field fails CI loudly instead of silently disabling a
resource type. Each file includes a negative control proving the check can
actually fail.

**Tooling**
- A Claude Code skill, `dangling-dns-finder`, for running an audit
  conversationally.

### Changed
- Supported providers went from three (AWS, GCP, Azure) to five.
- Collection is **parallelised** across accounts, regions, projects and
  compartments with a thread pool, tunable via `FINDMYTAKEOVER_MAX_WORKERS`
  (default 8).
- Findings are grouped by the provider owning the target rather than printed as
  one flat list.
- Exclusions are matched in a single vectorised pass, with IP rules evaluated
  by network containment instead of by expanding networks into addresses.
- Tests moved into `tests/`, and org-specific examples were removed from the
  sample configuration.
- Per-service error handling was tightened throughout: a service that is
  unavailable, unregistered, or that the caller lacks permission for now skips
  just that service instead of aborting the account or region being scanned.

### Fixed
- **API Gateway endpoints were stored with their `https://` scheme**, so they
  could never equal a bare DNS record value — every API-Gateway-backed record
  was reported as dangling.
- **An IPv6 CIDR in `exclude.ipaddress` crashed the run** with
  `AddressValueError`; both address families are now accepted.
- **Exclusion networks were expanded to individual addresses.** The sample
  config's own `100.1.0.0/16` became 65,536 entries, each costing a full scan of
  the results frame.
- The Azure collector imported `ResourceManagementClient` from a path that
  breaks on `azure-mgmt-resource` 26.x, where the parent became a namespace
  package with no top-level re-export. The import now works on 25.x and 26.x
  alike.
- An empty provider block in the config (for example `aws:` with nothing
  beneath it) parsed as `None` and crashed instead of being treated as
  disabled.
- Assorted collector bugs found while adding the Cloudflare and OCI providers.

### Security
- The passive DNS check makes outbound DNS queries by default. Timeouts and
  resolver errors are classified as inconclusive and never reported as
  findings; `--no-verify-dns` disables network lookups entirely.

## [1.1] — 2024-05-07

### Changed
- Configuration and collector updates carried forward from 1.0.

## [1.0] — 2023-08-05

Initial public release.

### Added
- Multi-cloud dangling DNS detection across **AWS, GCP and Azure**, without
  wordlists or brute forcing: DNS zones and infrastructure inventory are both
  enumerated from the configured accounts, then joined to find records whose
  backing resource no longer exists.
- DNS collection from Route 53, Google Cloud DNS and Azure DNS (A, AAAA and
  CNAME records), plus Route 53 alias records.
- Infrastructure inventory across the common public-facing services of each
  provider.
- Single YAML configuration file with per-provider enable flags, credentials
  and account lists, and `exclude` rules for IP ranges and domains.
- CLI with `--config-file` and `--dump-file`.
- Multi-account support: AWS via an assumed IAM role per account, GCP via a
  service-account key, Azure via a service principal.

### Later 1.x maintenance (2023–2025)
- Python 3.14 compatibility and general code cleanup (2025-11).
- Refactor of the cloud collectors and main script for clarity (2025-12).
- Roughly 123 dependency updates via Dependabot.
