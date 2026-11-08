#!/usr/bin/env bash
# Differential test: parse real-world GitHub workflows with yamlite and with
# PyYAML and compare the results. Needs python3 + PyYAML and network access.
#   bash scripts/yaml-difftest.sh
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
go build -o "$work/yamldiff" ./tools/yamldiff

urls=(
  actions/checkout/main/.github/workflows/test.yml
  zizmorcore/zizmor/main/.github/workflows/ci.yml
  cli/cli/trunk/.github/workflows/go.yml
  hashicorp/terraform/main/.github/workflows/build.yml
  prometheus/prometheus/main/.github/workflows/ci.yml
  argoproj/argo-cd/master/.github/workflows/ci-build.yaml
  helm/helm/main/.github/workflows/build-test.yml
  goreleaser/goreleaser/main/.github/workflows/build.yml
  sigstore/cosign/main/.github/workflows/build.yaml
  ossf/scorecard/main/.github/workflows/main.yml
  rust-lang/rust/master/.github/workflows/ci.yml
  python/cpython/main/.github/workflows/build.yml
  home-assistant/core/dev/.github/workflows/ci.yaml
  astral-sh/uv/main/.github/workflows/ci.yml
  pipe-cd/pipecd/master/.github/workflows/test.yaml
)
for u in "${urls[@]}"; do
  curl -fsSL --max-time 20 "https://raw.githubusercontent.com/$u" -o "$work/$(echo "$u" | tr / _)" || echo "skip $u"
done

python3 - "$work" <<'PY'
import json, subprocess, sys, pathlib, yaml
work = pathlib.Path(sys.argv[1])
def norm(v):
    if isinstance(v, dict): return {('on' if k is True else str(k)): norm(x) for k, x in v.items()}
    if isinstance(v, list): return [norm(x) for x in v]
    if v is None: return None
    if isinstance(v, bool): return str(v).lower()
    return str(v)
def low(v):
    if isinstance(v, dict): return {k: low(x) for k, x in v.items()}
    if isinstance(v, list): return [low(x) for x in v]
    if isinstance(v, str) and v in ("True", "False", "yes", "no"): return {"True": "true", "False": "false", "yes": "true", "no": "false"}[v]
    return v
bad = total = 0
for f in sorted(work.glob("*_*")):
    total += 1
    ref = low(norm(yaml.safe_load(f.read_text())))
    out = subprocess.run([str(work / "yamldiff"), str(f)], capture_output=True, text=True)
    got = low(json.loads(out.stdout)) if out.returncode == 0 else None
    if got != ref:
        bad += 1
        print("MISMATCH", f.name)
print(f"{total} workflows compared, {bad} mismatches")
sys.exit(1 if bad else 0)
PY
