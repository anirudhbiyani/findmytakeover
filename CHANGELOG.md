# Changelog

All notable changes to findmytakeover are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for 1.x predate this file and were reconstructed from git history, so
they summarise the shape of each release rather than listing every commit.

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
