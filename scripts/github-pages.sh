#!/usr/bin/env bash
# Start / stop / check this project's public website on GitHub Pages (free - nothing runs in AWS).
#
#   bash scripts/github-pages.sh up       # turn Pages on, enable the workflows, build and publish the site
#   bash scripts/github-pages.sh down     # take the site offline and pause its scheduled workflow
#   bash scripts/github-pages.sh status   # is it online? where? last build?
# (scripts/up.sh, down.sh and status.sh call this.) Needs the GitHub CLI, logged in: gh auth login
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPO_ROOT/../_setup/config.env" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/../_setup/config.env"
fi
: "${GITHUB_OWNER:=ObaidAbdullah16}"

# ---- per-project settings ------------------------------------------------------------
NAME="lifeline"
PAGES_WORKFLOW="self-scan.yml"          # builds and publishes the site
PAUSE_WORKFLOWS=(self-scan.yml)        # scheduled workflows paused by 'down'
extra_setup() { :; }                        # project-specific steps before the first build
# ----------------------------------------------------------------------------------------

REPO="${GITHUB_OWNER}/${NAME}"
log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$NAME" "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

command -v gh >/dev/null 2>&1 || die "gh is not installed (bash _setup/install-tools-wsl.sh)"
gh auth status >/dev/null 2>&1 || die "Log in to GitHub first: gh auth login"
gh repo view "$REPO" >/dev/null 2>&1 || die "$REPO is not on GitHub yet. Publish it: bash _setup/publish-to-github.sh $NAME"

pages_url() { gh api "repos/$REPO/pages" --jq '.html_url' 2>/dev/null || true; }

# wait_for_run <workflow file> <run id before we started it>
wait_for_run() {
  local wf="$1" prev="$2" id=""
  for _ in $(seq 1 30); do
    sleep 4
    id="$(gh run list --repo "$REPO" --workflow "$wf" --limit 1 --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
    [[ -n "$id" && "$id" != "$prev" ]] && break
    id=""
  done
  [[ -n "$id" ]] || { warn "Could not find the new run - check https://github.com/$REPO/actions"; return 0; }
  log "Building the site (run $id, usually 1-3 minutes)"
  gh run watch "$id" --repo "$REPO" --exit-status --interval 15 >/dev/null \
    || die "The build failed - open https://github.com/$REPO/actions/runs/$id"
}

case "${1:-status}" in
  up)
    if gh api "repos/$REPO/pages" >/dev/null 2>&1; then
      gh api --method PUT "repos/$REPO/pages" -f build_type=workflow >/dev/null
    else
      gh api --method POST "repos/$REPO/pages" -f build_type=workflow >/dev/null \
        || die "Could not turn on GitHub Pages (Settings > Pages > Source: GitHub Actions)"
    fi
    log "GitHub Pages is on (source: GitHub Actions)"
    for wf in "$PAGES_WORKFLOW" "${PAUSE_WORKFLOWS[@]}"; do
      gh workflow enable "$wf" --repo "$REPO" >/dev/null 2>&1 || true
    done
    extra_setup
    prev="$(gh run list --repo "$REPO" --workflow "$PAGES_WORKFLOW" --limit 1 --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
    gh workflow run "$PAGES_WORKFLOW" --repo "$REPO" --ref main >/dev/null || die "Could not start $PAGES_WORKFLOW"
    wait_for_run "$PAGES_WORKFLOW" "$prev"
    log "Online: $(pages_url)"
    ;;
  down)
    shift || true
    for a in "$@"; do [[ "$a" == "--all" ]] || die "unknown option: $a (use --all or nothing)"; done
    if gh api "repos/$REPO/pages" >/dev/null 2>&1; then
      gh api --method DELETE "repos/$REPO/pages" >/dev/null
      log "GitHub Pages site removed (the URL now shows 404)"
    else
      log "GitHub Pages was already off"
    fi
    # Pause the site's workflow too: with Pages off, its next run (e.g. on a push) would only fail.
    for wf in $(printf '%s\n' "$PAGES_WORKFLOW" "${PAUSE_WORKFLOWS[@]}" | sort -u); do
      gh workflow disable "$wf" --repo "$REPO" >/dev/null 2>&1 && log "Paused workflow $wf (up turns it on again)" || true
    done
    log "Down. The repository and its code stay on GitHub; nothing here ever cost money. Start again: bash scripts/up.sh"
    ;;
  status)
    url="$(pages_url)"
    if [[ -n "$url" ]]; then
      echo "$NAME: UP on GitHub Pages ($url, free)"
    else
      echo "$NAME: DOWN (GitHub Pages is off, free either way)"
    fi
    gh run list --repo "$REPO" --workflow "$PAGES_WORKFLOW" --limit 1 \
      --json conclusion,status,createdAt --jq '.[] | "  last site build: \(.status) \(.conclusion // "") \(.createdAt)"' 2>/dev/null || true
    ;;
  *) die "usage: $0 up|down|status" ;;
esac
