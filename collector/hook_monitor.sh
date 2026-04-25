#!/usr/bin/env bash
# Claude Code Hook Block Monitor
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

insert_count=0

# Ensure marker file exists
[[ -f /tmp/.guardian_hook_marker ]] || touch -t 197001010000 /tmp/.guardian_hook_marker

# Check Claude Code JSONL logs for hook blocks
mapfile -t logfiles < <(find $HOME/.claude/projects/ -name "*.jsonl" -newer /tmp/.guardian_hook_marker -type f 2>/dev/null || true)

for logfile in "${logfiles[@]}"; do
    [[ -z "$logfile" ]] && continue
    while IFS= read -r line; do
        reason=$(echo "$line" | grep -oP 'BLOCKED[^"]*' | head -1 || echo "unknown block")
        # Escape single quotes for SQL
        reason_safe=$(echo "$reason" | sed "s/'/''/g")
        logfile_safe=$(echo "$logfile" | sed "s/'/''/g")
        sqlite3 "$DB_PATH" "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) VALUES ('$NOW_UTC', 'claude_hook', 'blocked', 'local', 'claude', '{\"reason\":\"$reason_safe\",\"source\":\"$logfile_safe\"}', 1);"
        ((insert_count++))
    done < <(grep -i "BLOCKED" "$logfile" 2>/dev/null || true)
done

# Gitleaks scan (only with --full flag)
if [[ "${1:-}" == "--full" ]] && command -v gitleaks &>/dev/null; then
    for proj_dir in $HOME/projects/*/; do
        [[ -d "$proj_dir/.git" ]] || continue
        proj_name=$(basename "$proj_dir")
        output=$(cd "$proj_dir" && gitleaks detect --no-banner --no-color 2>&1 || true)
        if echo "$output" | grep -q "leaks found"; then
            leak_count=$(echo "$output" | grep -oP '\d+ leaks? found' | grep -oP '^\d+' || echo "0")
            detail="{\"project\":\"$proj_name\",\"leaks_found\":${leak_count:-0}}"
            sqlite3 "$DB_PATH" "INSERT INTO alerts (timestamp, severity, category, message, detail) VALUES ('$NOW_UTC', 'warning', 'gitleaks', 'Secrets detected in $proj_name: ${leak_count:-0} leaks', '$detail');"
        fi
    done
fi

touch /tmp/.guardian_hook_marker

sqlite3 "$DB_PATH" "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) VALUES ('hook_monitor', '$NOW_UTC', '{\"insert_count\":$insert_count}');"

echo "[hook_monitor] $insert_count hook events found"
