#!/usr/bin/env bash
# Tailscale Connection Logger
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

insert_count=0

# Snapshot current tailscale peers
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # tailscale status format: IP  HOSTNAME  USER  OS  STATUS
    ip=$(echo "$line" | awk '{print $1}')
    hostname=$(echo "$line" | awk '{print $2}')
    os=$(echo "$line" | awk '{print $4}')
    # Check if active (has "active" or direct connection info)
    status="idle"
    echo "$line" | grep -q "active" && status="active"

    detail="{\"hostname\":\"$hostname\",\"os\":\"$os\",\"status\":\"$status\"}"

    sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$NOW_UTC', 'tailscale', 'connection', '$ip', '$hostname', '$detail', 1);"
    ((insert_count++)) || true
done < <(tailscale status 2>/dev/null | grep -v "^$" | tail -n +1)

# Parse recent tailscaled journal for connection events (last 5 min)
LAST_TS=$(sqlite3 "$DB_PATH" "SELECT COALESCE(last_timestamp, '1970-01-01T00:00:00') FROM collector_state WHERE collector_name='tailscale'" 2>/dev/null || echo "1970-01-01T00:00:00")

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ts=$(echo "$line" | awk '{print $1"T"$2"Z"}' | sed 's/ /T/' || continue)
    # Look for peer connection / health events
    if echo "$line" | grep -qiE "peer|connect|handshake|health"; then
        detail=$(echo "$line" | sed 's/"/\\"/g' | cut -c1-500)
        sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$NOW_UTC', 'tailscale', 'event', '', 'tailscaled', '{\"log\":\"$detail\"}', 1);" 2>/dev/null || true
        ((insert_count++)) || true
    fi
done < <(journalctl -u tailscaled --since "5 minutes ago" --no-pager -q 2>/dev/null || true)

sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) VALUES ('tailscale', '$NOW_UTC', '{\"insert_count\":$insert_count}');"

echo "[tailscale_log] $insert_count events inserted"
