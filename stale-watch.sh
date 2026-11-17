#!/usr/bin/env bash
# PM2 cron (*/30): if kpi.csv is stale, restart aegis-watcher + one Telegram alert per incident
cd /mnt/c/github/aegis-watcher || exit 1
MAX_MIN=360
[ -f "$HOME/.config/aegis-stale/.env" ] && . "$HOME/.config/aegis-stale/.env"
ts(){ date -u +%FT%TZ; }
tg(){ [ -n "$TELEGRAM_BOT_TOKEN" ] && curl -s -m 10 "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
      -d chat_id="$TELEGRAM_CHAT_ID" --data-urlencode text="$1" >/dev/null; }
flag=/tmp/aegis-stale.flag
age=$(( ( $(date +%s) - $(stat -c %Y kpi.csv) ) / 60 ))
if [ "$age" -lt "$MAX_MIN" ]; then
  [ -f "$flag" ] && { rm -f "$flag"; tg "✅ aegis-watcher recovered (kpi.csv ${age} min old)"; }
  echo "$(ts) ok (kpi.csv ${age} min old)"; exit 0
fi
echo "$(ts) STALE kpi.csv ${age} min, restarting aegis-watcher" >&2
pm2 restart aegis-watcher >/dev/null
[ -f "$flag" ] || { touch "$flag"; tg "⚠️ aegis-watcher stale: kpi.csv not updated for ${age} min. Restarted it."; }
