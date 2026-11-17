#!/usr/bin/env bash
ts(){ date -u +%FT%TZ; }
cd /mnt/c/github/aegis-watcher || { echo "$(ts) ERR cannot cd" >&2; exit 1; }
# a crashed git can leave index.lock behind and block every later run
find .git -maxdepth 1 -name index.lock -mmin +10 -print -delete
git add kpi.csv
if git diff --cached --quiet; then echo "$(ts) no change ($(wc -l < kpi.csv) rows)"; exit 0; fi
git commit -qm "kpi snapshot $(date -u +%F)"
if git push -q origin main; then
  echo "$(ts) pushed $(git rev-parse --short HEAD) ($(wc -l < kpi.csv) rows)"
else
  echo "$(ts) PUSH FAILED" >&2; exit 1
fi
