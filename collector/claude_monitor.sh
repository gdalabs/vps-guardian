#!/usr/bin/env bash
# Claude Code Instance Monitor
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

insert_count=0

# Find all running claude processes
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    pid=$(echo "$line" | awk '{print $2}')
    user=$(echo "$line" | awk '{print $1}')
    cpu=$(echo "$line" | awk '{print $3}')
    mem_pct=$(echo "$line" | awk '{print $4}')
    rss_kb=$(echo "$line" | awk '{print $6}')
    tty=$(echo "$line" | awk '{print $7}')
    start_time=$(echo "$line" | awk '{print $9}')
    elapsed=$(echo "$line" | awk '{print $10}')

    # Try to detect working directory from /proc
    work_dir=""
    if [[ -d "/proc/$pid" ]]; then
        work_dir=$(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo "")
    fi

    # Extract project name from work_dir
    project_name=""
    if [[ "$work_dir" == *"/projects/"* ]]; then
        project_name=$(echo "$work_dir" | sed 's|.*/projects/||' | cut -d'/' -f1)
    elif [[ "$work_dir" == "$HOME" ]]; then
        project_name="(home)"
    fi

    sqlite3 "$DB_PATH" "INSERT INTO claude_instances (timestamp, pid, username, tty, mem_rss_kb, cpu_percent, start_time, elapsed, work_dir, project_name) VALUES ('$NOW_UTC', $pid, '$user', '$tty', $rss_kb, $cpu, '$start_time', '$elapsed', '$work_dir', '$project_name');"
    ((insert_count++)) || true
done < <(ps aux | grep -E "^[^ ]+ +[0-9]+ .* claude$" | grep -v grep || true)

sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) VALUES ('claude_monitor', '$NOW_UTC', '{\"instance_count\":$insert_count}');"

echo "[claude_monitor] $insert_count instances found at $NOW_UTC"
