#!/usr/bin/env bash
cd /mnt/c/github/aegis-watcher || exit 1
git add kpi.csv
git diff --cached --quiet && exit 0        # nothing changed, don't spam commits
git commit -qm "kpi snapshot $(date -u +%F)"
git push -q origin main
