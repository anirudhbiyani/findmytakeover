---
name: dangling-dns-finder
description: >-
  Detect dangling DNS records and subdomain-takeover risks in a DNS zone. Use
  whenever the user wants to find dangling domains/records, stale CNAMEs,
  subdomain takeover exposure, orphaned DNS entries, or audit a DNS zone (e.g.
  cloud.prophecy.io, example.com) for records pointing at deleted cloud
  resources — dead load balancers (ELBs), released EC2/GCP/Azure IPs, or expired
  SaaS targets. Triggers on "dangling domains", "dangling DNS", "subdomain
  takeover", "audit my DNS zone", "find stale/orphaned DNS records", "dead
  CNAMEs", or pointing at a Route53 zone and asking what's safe to delete. Works
  for ANY zone the user can dump (Route53 by default; bring-your-own records JSON
  otherwise).
---

# Dangling DNS Finder

Find DNS records that point at resources that no longer exist — the classic
subdomain-takeover setup. A `CNAME` to a deleted ELB or a SaaS tenant that was
cancelled, or an `A` record to a released cloud IP, can be silently reclaimed by
someone else and used to serve content under your domain.

## What counts as "dangling"

Two distinct, verifiable signals — keep them separate, they have different
confidence and different remediation:

1. **CNAME / ALIAS → NXDOMAIN.** The target hostname no longer resolves *at
   all*. For AWS this is definitive: if an ELB existed in any account, AWS's own
   authoritative DNS would answer. NXDOMAIN = the backing resource is gone.
   **High confidence.**
2. **A record → IP that isn't yours and doesn't respond.** The IP is absent from
   your cloud inventory (no EIP/ENI/static-address/instance owns it) *and* it
   doesn't answer HTTP. **Medium-high confidence** — see the caveats, this one
   has more ways to be wrong.

## Workflow

Run the bundled scripts in order. They are bash (run via `bash script.sh`, not
zsh — see Pitfalls). All write to an output dir you pass.

### 1. Scan the zone

```bash
bash scripts/find_dangling.sh <zone_name> <aws_profile> [outdir]
# e.g. bash scripts/find_dangling.sh cloud.prophecy.io dns ./out
```

This finds the Route53 hosted zone, dumps all records to `<outdir>/records.json`,
then:
- Resolves every CNAME/ALIAS target. NXDOMAIN is **re-checked against 8.8.8.8 and
  1.1.1.1** before being trusted (a single resolver can flake). → `dangling_cname.tsv`
- Categorizes each target so validation records aren't misreported as takeovers
  (see Classification). → category column
- HTTP-probes every A-record host; no response = candidate. → `dangling_a.tsv`

If the zone is **not** in Route53, skip the dump and hand the script a records
JSON in the same shape (`{"ResourceRecordSets":[...]}`) — or just run the
resolution/liveness logic against a list of names you already have.

### 2. (Recommended) Confirm A-record candidates against cloud inventory

Liveness alone is a heuristic. For real confidence on A records, cross-reference
the IPs against what your accounts actually own:

```bash
bash scripts/audit_a_inventory.sh <outdir> [aws_profiles] [gcp] [azure]
# e.g. bash scripts/audit_a_inventory.sh ./out "dns prof-prod staging" yes yes
```

An A-record IP that is **both** absent from every account's inventory **and**
unreachable over HTTP is a genuine dangling candidate. An IP that responds — even
404 — is in use (often via a load-balancer/forwarding-rule IP that doesn't show
up in a plain instance/EIP listing), so treat it as live and keep it.

### 3. Report

Present a single consolidated table: **IP/Target · Cloud · Subdomain**, grouped
by category, with counts. State confidence per bucket and call out anything
sensitive (customer-named subdomains, `*-prod` hosts) for manual confirmation
before deletion.

### 4. Generate the delete command (show, don't run)

```bash
bash scripts/build_delete_batch.sh <outdir>/records.json <names.txt> <outdir>/delete-batch.json
```

`names.txt` = one FQDN per line **with trailing dot**, matching record names
(`find_dangling.sh` writes `dangling_names.txt` for the takeover-risk set and
`validation_names.txt` for stale validation records). Then show the user:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id <ZID> \
  --change-batch file://<outdir>/delete-batch.json \
  --profile <profile>
```

Default to **showing** the command and letting the user run it. DNS deletion is
hard to reverse and outward-facing — only run it yourself if the user explicitly
says so. The build step prints a count; it must equal your name list before the
delete is safe to run.

## Classification — what is NOT a takeover risk

Plenty of records resolve to nothing or look dead but are harmless. Don't report
these as dangling domains; bucket them separately as "stale, optional cleanup":

- **ACM cert validation** — CNAME → `*.acm-validations.aws`. Normal; resolves to
  no A record. Stale only if the cert is gone.
- **Google cert-manager validation** — CNAME → `*.authorize.certificatemanager.goog`.
  `_acme-challenge_*` names. Single-use DNS-01 tokens, **not** service endpoints —
  even when NXDOMAIN they are not a takeover vector.
- **DKIM / email auth** — CNAME → `*.dkim.*`, `*.custdkim.salesforce.com`,
  `*.hubspotemail.net`, `*.domainkey.*`, `*.deliver.highspot.com`, `freshemail.io`.
  These point into live SaaS provider zones; `NOERROR` with no A record is expected.
- **MX / TXT / NS / SOA** — out of scope; never delete as part of this.

Only a CNAME/ALIAS whose target is a real endpoint (ELB, cloud host, app) AND
returns NXDOMAIN is a takeover risk.

## Pitfalls (these cost real time — heed them)

- **Run scripts with `bash`, not zsh.** In zsh `status` is a read-only variable;
  a loop doing `status=$(...)` dies instantly. The scripts use `bash` shebangs and
  the var name `st` — keep it that way.
- **macOS has no `timeout`/`gtimeout`.** Don't rely on it. Use `curl -m <secs>`
  for bounded network calls (the scripts do).
- **Raw `/dev/tcp` port probes are often blocked** outbound from a dev machine —
  they return uniform failure and look like "everything is dead." Use `curl -m`
  for liveness, and sanity-check the probe against a known-live host first.
- **"Not in my cloud inventory" ≠ dangling for GCP/Azure.** Plain
  instance/address listings miss GKE/LB forwarding-rule IPs and any project you
  lack read access to. Always confirm with an HTTP liveness probe; an IP that
  answers is in use even if your inventory sweep didn't find it.
- **A live VM firewalled from you can false-positive as dead.** If the whole
  inventory of live IPs also responds, blanket-firewalling isn't happening and
  confidence is high — but still spot-check `*-prod` / customer hosts before
  deleting.
- **Escaped record names** (e.g. `\100.example.com`, octal/decimal escapes,
  wildcards `\052` = `*`) break naive `curl` probes — the script skips them; verify
  those by reading the record's value directly (`dig` / the zone dump), don't
  assume dead.
- **Verify NXDOMAIN across multiple resolvers** (8.8.8.8 + 1.1.1.1) before
  trusting it. The script does this for you.
- **Zones can live in different accounts/profiles.** Don't assume one profile
  owns every zone — look the zone up per profile, and run the delete with the
  profile that actually owns it.
- **`build_delete_batch.sh` matches by name**, so it removes *all* record types
  at a matched name. That's fine for single-type danglers; if a dangling name
  also carries a record you want to keep (e.g. a TXT), edit the batch by hand.

## Self-check

`bash scripts/selftest.sh` asserts the target classifier (ACM / cert-manager /
DKIM / endpoint) still buckets correctly. Run it after editing the classifier.
