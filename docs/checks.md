# Lifeline checks

Each check returns **pass (10)**, **warn (5)** or **fail (0)**, or **skip** when Lifeline cannot see
the data (no domain, no token, no `lifeline.yml`). Skipped checks do not lower the score; they lower
**coverage**, which is always printed next to the score so a high score on little data is obvious.

The overall score is the weighted average of evaluated checks (weights below), 0-10.

## Domain & TLS

### ll-dom-001
**Domain registration does not expire soon** (weight 10). RDAP lookup via the rdap.org bootstrap,
walking up from the given host to the registrable domain. Pass ≥ 90 days left, warn 30-89, fail < 30.
Skipped for TLDs without RDAP, and when the registry's RDAP record has no expiry date (the domain it
names is still used as the registrable domain by the DNSSEC and email checks).
*Why:* an expired domain takes down the website, email, package download URLs and OAuth callbacks at once,
and dropped domains are bought by squatters. Fix: auto-renew, multi-year renewal, two people with registrar access.

### ll-dom-002
**TLS certificate is valid and not about to expire** (weight 10). Connects to port 443, verifies the
chain and hostname with the system roots. Pass ≥ 14 days left, warn 7-13, fail < 7 or invalid.
Thresholds suit automated 45-90 day certificates.

### ll-dom-003
**CAA record** (weight 3). DNS-over-HTTPS lookup of CAA on the host and its parents. Warn when absent.

### ll-dom-004
**DNSSEC** (weight 3). Looks for a DS record at the parent, then asks a validating resolver for the
zone's own SOA record. Pass when the answer is validated (AD flag). **Fail** when the resolver answers
SERVFAIL: validation fails ("bogus"), which is an outage for every validating resolver. Warn when the
zone is unsigned, or signed but the answer isn't marked validated. The zone apex is queried rather than
the scanned host because a host such as `www` is often a CNAME to an unsigned CDN, which is normal
("insecure"), not broken.

### ll-dom-005
**SPF and DMARC** (weight 5). Pass with SPF and DMARC `p=quarantine|reject`; warn with `p=none` or one of the two;
fail with neither. Also warns when SPF ends in `+all` (or a bare `all`, which means the same), when there is more
than one SPF or DMARC record (receivers then ignore them), or when DMARC has no `p=` tag.
Domains that send no email should publish `v=spf1 -all` and `p=reject`.

### ll-dom-006
**DKIM** (weight 3). Looks for a DKIM key (TXT with `p=`) at `<selector>._domainkey.<domain>` for the
selectors listed under `dkim_selectors:` in lifeline.yml, then 25 common ones (Google, Microsoft 365, Zoho,
Mailchimp, SendGrid, Fastmail, Proton, ImprovMX...). Pass when a key is found; warn when only revoked keys (empty `p=`)
or none are found - DKIM selectors cannot be listed from outside, so "none found" is a warning, not a failure.
Skipped for domains that send and receive no mail (`v=spf1 -all` and no MX).

### ll-dom-007
**SPF lookup limit** (weight 2). Counts the DNS-querying terms (`include`, `a`, `mx`, `ptr`, `exists`,
`redirect`) through every include, as receivers do (RFC 7208 allows 10). Pass up to 8, warn at 9-10, fail above
10: receivers then return *permerror* and SPF stops protecting the domain - common after adding a CRM, a helpdesk
and a newsletter tool. Include loops are reported and stopped.

*Registrable domain:* DNSSEC and email checks run on the registrable domain. Lifeline takes it from RDAP;
without RDAP it uses the last two labels, or three for common two-label suffixes such as `co.uk` and `co.in`
(a short built-in list instead of the full Public Suffix List, to stay dependency-free).

## Access & bus factor

### ll-acc-001
**More than one person can administer the project** (weight 8). Personal-account repositories fail
(one person holds every key). Organisations pass with 2-5 visible owners and warn above 5. Below 2 the
result depends on what the token can see: an organisation owner's token sees every owner, so one owner
**fails**; any other token sees public memberships only, so one visible owner is a **warning** ("confirm
with an owner's token"), and none visible is a skip.

### ll-acc-002
**Organisation requires 2FA** (weight 8). Only visible to organisation owners; skipped otherwise.

### ll-acc-003
**Default branch is protected** (weight 8). Classic branch protection or any ruleset on the default branch.

### ll-acc-004
**Bus factor** (weight 6). Number of humans who made 80% of the last 300 commits (180 days), bots excluded.
Pass ≥ 3, warn 2, fail 1. Warn when there were no commits at all.

### ll-acc-005
**Security contact** (weight 3). `security_contact` in lifeline.yml, a SECURITY.md (root, .github/ or docs/),
or a `/.well-known/security.txt` with a Contact line. Works with `--path` alone (a local checkout).

## CI hygiene

### ll-ci-001
**Actions pinned to commit SHAs** (weight 8). Share of non-local `uses:` references pinned to a 40-character SHA
(or an image digest). Points = share × 10, rounded down (19 of 20 pinned = 9); pass only at 100%, warn ≥ 50%, fail below.

### ll-ci-002
**Token permissions restricted** (weight 6). Fail on `permissions: write-all`; warn when a workflow has no
top-level `permissions:` and some jobs have none either.

### ll-ci-003
**No "pwn request"** (weight 10). Fail when a workflow triggered by `pull_request_target`, `workflow_run` or
`issue_comment` (all three run with secrets and a write token) fetches pull-request code: `actions/checkout`
with a `ref` or `repository` pointing at the PR head, its merge commit or a step output named `*head*`;
`gh pr checkout`; or `git fetch/checkout` of `pull/<n>/head`. Artifact poisoning (a `workflow_run` job
that downloads and runs a PR's build output) is not detected yet - use zizmor for that.

*Unparsable workflows:* if a workflow file cannot be parsed, the CI checks list it under "not analysed",
and a result that would have passed becomes a warning: an unread file is not a clean file.

### ll-ci-004
**Cloud access through OIDC** (weight 8). Fail when `AWS_ACCESS_KEY_ID`-style secrets or
`aws-access-key-id` inputs appear.

### ll-ci-005
**Automatic updates** (weight 4). Dependabot covering `github-actions`, or a Renovate config.

## Backup independence (needs lifeline.yml)

### ll-bak-001
**Backups declared** (weight 8). Fail when `backups:` is missing or empty.

### ll-bak-002
**Restores tested** (weight 8). Worst backup decides: pass ≤ 90 days since `last_restore_test`, warn ≤ 180,
fail older or never. A date in the future is a warning (usually a typo).

### ll-bak-003
**Backups isolated** (weight 8). Warn for any backup not marked `isolated: true` (different account,
credentials or object lock). In April 2026 an AI coding agent deleted a company's production database
*and* its backups because one credential could delete both.

## Cost runway (needs lifeline.yml)

### ll-cost-001
**Runway ≥ 6 months** (weight 8). `(usable credits + cash) / monthly spend`, where credits that will
expire before they can be spent do not count. Pass ≥ 180 days, warn 60-179, fail < 60.
Also warns when credits expire within 60 days.

### ll-cost-002
**Billing alerts configured** (weight 4). `budget_alerts: true` in lifeline.yml.

## Ignoring checks

List check IDs under `ignore:` in lifeline.yml, with a comment saying why. A trailing `*` ignores a group:
`LL-BAK-*` for a project with no state to back up. Ignored checks are skipped, so they lower coverage, not the score.
Unknown keys in lifeline.yml (for example `last_restore_tested`) are reported as warnings instead of being
silently ignored.

## Limits (stated honestly)

- Manifest-based checks trust what the maintainer writes. Lifeline makes the claims explicit and
  reviewable in a pull request; it does not verify cloud accounts.
- Access checks see more with an organisation owner's token than with the default Actions token.
- Without `GITHUB_TOKEN`, GitHub allows 60 API requests an hour (roughly two scans). A rate-limited
  check is reported as an **error**, not a skip, and `lifeline batch` leaves scans below 50% coverage out
  of the median.
- Domain checks depend on public RDAP/DoH services (rdap.org, Cloudflare, Google) being reachable.
