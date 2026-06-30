#!/usr/bin/env bash
# VS Code Remote Tunnel Activity Detector
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

insert_count=0

# Detect running VS Code server processes
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    pid=$(echo "$line" | awk '{print $2}')
    user=$(echo "$line" | awk '{print $1}')
    start=$(echo "$line" | awk '{print $9}')
    mem=$(echo "$line" | awk '{print $4}')
    cpu=$(echo "$line" | awk '{print $3}')

    detail="{\"pid\":$pid,\"user\":\"$user\",\"cpu\":\"$cpu\",\"mem\":\"$mem\",\"start\":\"$start\"}"

    sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$NOW_UTC', 'vscode_tunnel', 'connection', 'local', '$user', '$detail', 1);"
    ((insert_count++)) || true
done < <(ps aux | grep "[.]vscode/cli/servers" | grep -v grep | grep -v "cpuUsage\|shellIntegration" || true)

# Detect VS Code terminal sessions (spawned by tunnel)
# grep -vc prints "0" AND exits 1 on no match; under pipefail that combined
# with `|| echo 0` produced a two-line "0\n0" that broke the arithmetic test.
term_count=$(ps aux | grep "shellIntegration-bash.sh" | grep -vc grep || true)
term_count=${term_count:-0}
if [[ "$term_count" -gt 0 ]]; then
    detail="{\"terminal_sessions\":$term_count}"
    sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$NOW_UTC', 'vscode_tunnel', 'terminal_active', 'local', '$(whoami)', '$detail', 1);"
    ((insert_count++)) || true
fi

sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) VALUES ('vscode_tunnel', '$NOW_UTC', '{\"insert_count\":$insert_count}');"

echo "[vscode_tunnel] $insert_count events inserted"
