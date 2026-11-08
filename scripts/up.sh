#!/usr/bin/env bash
# Start: publish this project's website on GitHub Pages (free).
#   bash scripts/up.sh
exec bash "$(dirname "${BASH_SOURCE[0]}")/github-pages.sh" up "$@"
