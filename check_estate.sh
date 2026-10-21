#!/usr/bin/env bash
# check_estate.sh — one-command, read-only php2shell attempt sweep of local logs.
#
# Finds web-server log directories, runs php2shell_scan.py over them, prints
# per-directory hit counts and a final verdict. Exit 1 if any fingerprint is
# found, 0 if clean, 2 if nothing could be scanned.
#
# It NEVER writes to the logs, NEVER restarts anything, NEVER sends an exploit
# or any traffic. Add your own log roots below or via $EXTRA_LOG_DIRS
# (colon-separated).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCANNER="${SCANNER:-$HERE/php2shell_scan.py}"

[ -x "$SCANNER" ] || SCANNER="$HERE/../php2shell_scan.py"
command -v python3 >/dev/null || { echo "need python3"; exit 2; }

declare -a DIRS=()
add_dir() {
  local d="$1"
  [ -d "$d" ] || return 0
  local real; real=$(realpath "$d" 2>/dev/null) || return 0
  local x
  for x in "${DIRS[@]:-}"; do [ "$x" = "$real" ] && return 0; done
  DIRS+=("$real")
}

# Known web-log locations; extend to taste.
for d in /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/caddy \
         /var/log/traefik /var/log/haproxy /var/log/openresty \
         "$HOME/.pm2/logs" "$HOME/.local/share/caddy/logs"; do
  add_dir "$d"
done
IFS=':' read -ra EXTRA <<< "${EXTRA_LOG_DIRS:-}"
for d in "${EXTRA[@]:-}"; do add_dir "$d"; done

echo "== php2shell local estate check =="
if [ "${#DIRS[@]}" -eq 0 ]; then
  echo "no web-log directories found; nothing scanned"
  exit 2
fi

STATUS=0
for d in "${DIRS[@]}"; do
  echo "-- $d"
  if ls "$d"/*access* "$d"/*.log >/dev/null 2>&1; then
    if ! python3 "$SCANNER" --quiet --access-log "$d/*access*" --access-log "$d"/*.log; then
      STATUS=1
      python3 "$SCANNER" --access-log "$d/*access*" --access-log "$d"/*.log | head -20
    else
      echo "   clean"
    fi
  else
    echo "   (no log files)"
  fi
done

if [ "$STATUS" -eq 0 ]; then
  echo "RESULT: no php2shell fingerprints found in scanned local logs"
else
  echo "RESULT: php2shell fingerprints FOUND — inspect the lines above"
fi
exit $STATUS
