#!/usr/bin/env bash
# Docker & Service Status Collector
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

insert_count=0

# Docker containers
while IFS='|' read -r name image status ports; do
    [[ -z "$name" ]] && continue
    detail="{\"image\":\"$image\",\"status\":\"$status\",\"ports\":\"$ports\"}"
    state="running"
    echo "$status" | grep -qi "exited\|stopped" && state="stopped"

    sqlite3 "$DB_PATH" "INSERT INTO service_status (timestamp, service_name, service_type, status, detail) VALUES ('$NOW_UTC', '$name', 'docker', '$state', '$detail');"
    ((insert_count++)) || true
done < <(docker ps -a --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" 2>/dev/null || true)

# Key systemd services
for svc in ssh tailscaled docker fail2ban code-tunnel@* filebrowser; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
    [[ "$status" == "not-found" ]] && continue
    detail="{}"
    if [[ "$status" == "active" ]]; then
        uptime_info=$(systemctl show "$svc" --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2 || echo "")
        detail="{\"since\":\"$uptime_info\"}"
    fi
    sqlite3 "$DB_PATH" "INSERT INTO service_status (timestamp, service_name, service_type, status, detail) VALUES ('$NOW_UTC', '$svc', 'systemd', '$status', '$detail');"
    ((insert_count++)) || true
done

# Listening ports summary
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    addr=$(echo "$line" | awk '{print $4}')
    process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
    port=$(echo "$addr" | rev | cut -d: -f1 | rev)
    bind_ip=$(echo "$addr" | rev | cut -d: -f2- | rev)

    exposure="localhost"
    [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "[::]" || "$bind_ip" == "*" ]] && exposure="public"
    echo "$bind_ip" | grep -q "100\." && exposure="tailscale"

    detail="{\"bind\":\"$addr\",\"process\":\"$process\",\"exposure\":\"$exposure\"}"
    sqlite3 "$DB_PATH" "INSERT INTO service_status (timestamp, service_name, service_type, status, detail) VALUES ('$NOW_UTC', 'port:$port', 'listening_port', '$exposure', '$detail');"
    ((insert_count++)) || true
done < <(ss -tlnp 2>/dev/null | tail -n +2 || true)

sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) VALUES ('docker_status', '$NOW_UTC', '{\"insert_count\":$insert_count}');"

echo "[docker_status] $insert_count entries at $NOW_UTC"
