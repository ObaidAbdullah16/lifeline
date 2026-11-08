#!/usr/bin/env bash
# Stop: take the GitHub Pages site offline and pause its scheduled workflow (free either way).
#   bash scripts/down.sh        (--all does the same: nothing is kept anywhere that costs money)
exec bash "$(dirname "${BASH_SOURCE[0]}")/github-pages.sh" down "$@"
