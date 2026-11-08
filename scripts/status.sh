#!/usr/bin/env bash
# Is the GitHub Pages site online?
#   bash scripts/status.sh
exec bash "$(dirname "${BASH_SOURCE[0]}")/github-pages.sh" status "$@"
