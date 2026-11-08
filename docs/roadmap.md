# Roadmap

| Milestone | Target | Scope | Status |
|---|---|---|---|
| v0.1 | Nov 2026 (week 1) | CLI skeleton, domain expiry + TLS checks | done in this repo |
| v0.2 | Dec 2026 | 20 checks in 5 areas, lifeline.yml, text/JSON/Markdown | done in this repo |
| v0.3 | Jan 2027 | GitHub Action, SARIF, badge, score-drop issues, HTML report, releases signed with cosign | done in this repo - needs first tag `v0.3.0` |
| v0.3.1 | Nov 2026 | DKIM and SPF lookup-limit checks; domain-only scans for the email/domain add-on | done in this repo |
| Scan | Feb 2027 | `lifeline batch` over ~100 public CNCF/FOSS projects; publish an anonymised "state of open-source operations" report; open friendly issues offering the tool | tool ready (`lifeline batch`), scan to be run |
| v0.4 | Mar-May 2027 | Import zizmor JSON for deeper CI analysis; GitLab/Codeberg repositories; repository-mirror detection; `lifeline init` to write lifeline.yml interactively | planned |
| v0.5 | later | Optional read-only cloud checks (S3 object lock, cross-account snapshot copies) behind a build tag, keeping the default binary dependency-free | idea |

## Funding

See [grant-notes.md](grant-notes.md). Lifeline itself is a deterministic tool (no AI in the checks), but its
first versions were written with an AI assistant; some funders (NLnet since October 2026) restrict AI-generated
work, so read the grant notes before applying.

## How to help

- Run `lifeline scan --repo your/project` and open an issue if a check is wrong for your setup.
- Add RDAP coverage notes for TLDs that fail.
- Improve `internal/yamlite` against odd real-world workflows (`scripts/yaml-difftest.sh`).
