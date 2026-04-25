#!/usr/bin/env bash
# SSH Access Log Collector — parses auth.log and inserts into SQLite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
WHITELIST="${SCRIPT_DIR}/../analyzer/whitelist.json"

NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Get last processed timestamp
LAST_TS=$(sqlite3 "$DB_PATH" "SELECT COALESCE(last_timestamp, '1970-01-01T00:00:00') FROM collector_state WHERE collector_name='ssh'" 2>/dev/null || echo "1970-01-01T00:00:00")

# Load whitelist IPs into a lookup string
WL_IPS=""
if [[ -f "$WHITELIST" ]]; then
    WL_IPS=$(python3 -c "
import json, sys
with open('$WHITELIST') as f:
    data = json.load(f)
ips = set()
for group in data.values():
    if isinstance(group, dict):
        ips.update(group.keys())
print(' '.join(ips))
" 2>/dev/null || echo "")
fi

is_whitelisted() {
    local ip="$1"
    for wip in $WL_IPS; do
        [[ "$ip" == "$wip" ]] && echo 1 && return
    done
    echo 0
}

insert_count=0

# Parse successful logins: "Accepted publickey/password for USER from IP port PORT"
while IFS= read -r line; do
    # Extract timestamp (ISO 8601 with timezone)
    ts=$(echo "$line" | grep -oP '^\S+')
    # Convert to UTC
    ts_utc=$(date -u -d "$ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || continue)

    # Skip if already processed
    [[ "$ts_utc" < "$LAST_TS" || "$ts_utc" == "$LAST_TS" ]] && continue

    if echo "$line" | grep -qP 'Accepted (publickey|password)'; then
        user=$(echo "$line" | grep -oP 'for \K\S+')
        ip=$(echo "$line" | grep -oP 'from \K[\d.]+')
        method=$(echo "$line" | grep -oP 'Accepted \K\S+')
        port=$(echo "$line" | grep -oP 'port \K\d+')
        key_fp=$(echo "$line" | grep -oP 'SHA256:\S+' || echo "")
        wl=$(is_whitelisted "$ip")
        detail="{\"auth_method\":\"$method\",\"port\":$port,\"key_fingerprint\":\"$key_fp\"}"

        sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$ts_utc', 'ssh', 'login', '$ip', '$user', '$detail', $wl);"
        ((insert_count++)) || true
    fi
done < <(sudo grep -E "Accepted (publickey|password)" /var/log/auth.log 2>/dev/null || true)

# Parse failed logins: "Failed password for [invalid user] USER from IP"
while IFS= read -r line; do
    ts=$(echo "$line" | grep -oP '^\S+')
    ts_utc=$(date -u -d "$ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || continue)
    [[ "$ts_utc" < "$LAST_TS" || "$ts_utc" == "$LAST_TS" ]] && continue

    ip=$(echo "$line" | grep -oP 'from \K[\d.]+')
    port=$(echo "$line" | grep -oP 'port \K\d+' || echo "0")

    if echo "$line" | grep -q "invalid user"; then
        user=$(echo "$line" | grep -oP 'invalid user \K\S+')
    else
        user=$(echo "$line" | grep -oP 'for \K\S+')
    fi

    wl=$(is_whitelisted "$ip")
    detail="{\"port\":${port:-0},\"invalid_user\":$(echo "$line" | grep -qc 'invalid user')}"

    sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$ts_utc', 'ssh', 'failed', '$ip', '$user', '$detail', $wl);"
    ((insert_count++)) || true
done < <(sudo grep "Failed password" /var/log/auth.log 2>/dev/null | grep -v "message repeated" || true)

# Update collector state
sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) VALUES ('ssh', '$NOW_UTC', '{\"insert_count\":$insert_count}');"

echo "[ssh_access] $insert_count events inserted (since $LAST_TS)"
