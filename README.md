# Lifeline

[![CI](https://github.com/ObaidAbdullah16/lifeline/actions/workflows/ci.yml/badge.svg)](https://github.com/ObaidAbdullah16/lifeline/actions/workflows/ci.yml)
[![Lifeline score](https://img.shields.io/endpoint?url=https%3A%2F%2Fobaidabdullah16.github.io%2Flifeline%2Flifeline-badge.json)](https://obaidabdullah16.github.io/lifeline/)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)

**An open-source operational-resilience scorecard for open-source projects and small teams.**

[OpenSSF Scorecard](https://github.com/ossf/scorecard) grades how a repository is *built*. Lifeline grades
whether the project's *operations* would survive a bad day:

| Area | What can go wrong | What Lifeline checks |
|---|---|---|
| Domain & TLS | Domain expires, certificate lapses, email spoofed | RDAP expiry, certificate validity, CAA, DNSSEC, SPF/DMARC, DKIM, SPF lookup limit |
| Access & bus factor | One person holds every key and disappears | Owners, 2FA, branch protection, commit concentration, security contact |
| CI hygiene | A hijacked action tag steals secrets | SHA pinning, token permissions, pwn requests, long-lived cloud keys, Dependabot |
| Backup independence | Backups deleted with the same credentials as production | Declared backups, restore-test age, isolation |
| Cost runway | Cloud credits run out silently | Days of runway, billing alerts |

22 checks, one 0-10 score, **always printed with its coverage** so a high score on little data is obvious.

## Quick start

```bash
go install github.com/ObaidAbdullah16/lifeline/cmd/lifeline@latest   # or download a signed release binary

export GITHUB_TOKEN=$(gh auth token)          # optional for one scan, needed for batch (60 requests/hour without)
lifeline scan --repo kyverno/kyverno --domain kyverno.io
lifeline scan --path . --format md            # local checkout + lifeline.yml
lifeline scan --repo owner/name --json r.json --html r.html --sarif r.sarif --badge badge.json
lifeline batch --targets examples/targets.txt --out results/   # many projects, anonymised summary
lifeline checks                                                 # list all checks
```

Example (trimmed):

```
Lifeline v0.3.1  acme/app / acme.example
SCORE 6.4/10 (fragile)  coverage 85%

== Domain & TLS  8.6/10
  [PASS] LL-DOM-001  acme.example expires on 2027-08-01, in 281 days (registrar: Example Registrar)
  [WARN] LL-DOM-003  no CAA record: any certificate authority may issue certificates for this domain
== Access & bus factor  4.4/10
  [FAIL] LL-ACC-001  owned by the personal account "acme": one person holds every key
  [FAIL] LL-ACC-004  bus factor 1: 1 author(s) made 80% of the last 214 commits (180 days)
```

### Domain and email only

Every domain check works without a repository, which makes Lifeline a quick outside-in review of a
company's domain - no access needed, only public DNS, RDAP and TLS:

```bash
lifeline scan --domain example.com --format md      # expiry, TLS, CAA, DNSSEC, SPF/DMARC, DKIM, SPF lookups
```

This is the engine of the **email and domain security** add-on I sell to small businesses: a before/after
score and the staged move to DMARC `p=reject` in [docs/email-domain-runbook.md](docs/email-domain-runbook.md).
Add `dkim_selectors:` to lifeline.yml when a provider uses an unusual selector.

## GitHub Action

```yaml
permissions: {}
jobs:
  scorecard:
    runs-on: ubuntu-latest
    permissions: { contents: read, issues: write, security-events: write }
    steps:
      - uses: actions/checkout@<sha> # v7
        with: { persist-credentials: false }
      - uses: ObaidAbdullah16/lifeline@<sha> # v0.3.1
        with:
          open-issue-on-drop: "true"   # issue when the score drops vs. the previous run
          upload-sarif: "true"         # failing checks in the Security tab
```

The action builds Lifeline from source (no downloads, no third-party code), writes the Markdown report to
the job summary, and outputs `score`, `delta` and `report-dir` (JSON, HTML, SARIF, badge). See
[`examples/workflow.yml`](examples/workflow.yml). This repository runs it on itself every week and publishes
the report and badge to GitHub Pages (`bash scripts/up.sh` turns the scorecard site on and publishes it,
`bash scripts/down.sh` takes it offline and pauses the weekly scan, `bash scripts/status.sh` shows it).

## lifeline.yml

Backups and money cannot be seen from outside, so Lifeline asks for them explicitly - which also makes
the claims reviewable in a pull request. See [`examples/lifeline.yml`](examples/lifeline.yml) and this
repository's own [`lifeline.yml`](lifeline.yml) (it honestly fails the restore-test check today).
Unknown keys are reported as warnings, so a typo cannot silently turn a check off.

## Design choices

- **Zero third-party Go modules.** A security tool should not widen its users' supply chain. YAML is
  parsed by [`internal/yamlite`](internal/yamlite), DNS is DNS-over-HTTPS JSON, RDAP is plain HTTP+JSON.
  CI fails if `go.mod` gains a `require`.
- **Differentially tested parser.** `scripts/yaml-difftest.sh` compares yamlite with PyYAML on real
  workflows from large projects (Rust, CPython, Terraform, Prometheus, Argo CD, Home Assistant...): 0 mismatches.
- **Deterministic, explainable checks.** No AI; every result has a summary, details and a fix.
- **Honest coverage.** Skipped checks never inflate the score.
- **Signed releases.** GoReleaser builds for Linux/macOS/Windows, generates SBOMs, and signs the checksum
  file keylessly with cosign (Sigstore bundle `checksums.txt.sigstore.json`).

Verify a release:

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/ObaidAbdullah16/lifeline/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c checksums.txt --ignore-missing
```

## Documentation

- [Every check, its thresholds and limits](docs/checks.md)
- [Roadmap](docs/roadmap.md) · [Grant notes](docs/grant-notes.md) · [Report template](docs/state-of-ops-report-template.md)

## How this project was built

Lifeline's first versions (code and documentation) were written with the help of an AI coding assistant.
The maintainer is responsible for every line: changes are checked by review, by `go test -race` with
fake GitHub, DNS, RDAP and TLS servers, and by the differential YAML test below. This note is kept up to
date because some funders and users want to know how a project is made.

## Development

```bash
go test -race -cover ./...      # unit tests use httptest fakes for GitHub, DoH, RDAP and TLS
bash scripts/yaml-difftest.sh   # optional, needs python3 + PyYAML + network
```

MIT licensed. Security issues: see [SECURITY.md](SECURITY.md).
