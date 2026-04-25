#!/usr/bin/env bash
# Resource Snapshot Collector — CPU/Mem/Disk/Net/Load
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/../data/access_log.db"
NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# CPU usage (average across all cores, 1-second sample)
cpu_percent=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' 2>/dev/null || echo 0)

# Memory
read -r mem_total mem_used mem_available < <(free -m | awk '/^Mem:/ {print $2, $3, $7}')
read -r swap_total swap_used < <(free -m | awk '/^Swap:/ {print $2, $3}')

# Disk (root partition)
read -r disk_total disk_used disk_avail < <(df -BG / | awk 'NR==2 {gsub("G",""); print $2, $3, $4}')

# Network I/O (total across all interfaces, cumulative bytes)
read -r net_rx net_tx < <(cat /proc/net/dev | awk 'NR>2 && $1 !~ /lo:/ {rx+=$2; tx+=$10} END {print rx, tx}')

# Load average
read -r load_1 load_5 load_15 < <(cat /proc/loadavg | awk '{print $1, $2, $3}')

sqlite3 "$DB_PATH" "INSERT INTO resource_snapshot (timestamp, cpu_percent, mem_total_mb, mem_used_mb, mem_available_mb, swap_total_mb, swap_used_mb, disk_total_gb, disk_used_gb, disk_avail_gb, net_rx_bytes, net_tx_bytes, load_1, load_5, load_15) VALUES ('$NOW_UTC', $cpu_percent, $mem_total, $mem_used, $mem_available, $swap_total, $swap_used, $disk_total, $disk_used, $disk_avail, $net_rx, $net_tx, $load_1, $load_5, $load_15);"

echo "[resource_snap] snapshot taken at $NOW_UTC — CPU:${cpu_percent}% Mem:${mem_used}/${mem_total}MB Disk:${disk_used}/${disk_total}GB Load:${load_1}"
