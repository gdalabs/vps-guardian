#!/usr/bin/env bash
# VPS Guardian — Run all collectors + anomaly detection
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR_DIR="${SCRIPT_DIR}/collector"

echo "=== VPS Guardian Collection Run: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

python3 "$COLLECTOR_DIR/ssh_access.py"
bash "$COLLECTOR_DIR/tailscale_log.sh"
bash "$COLLECTOR_DIR/vscode_tunnel.sh"
bash "$COLLECTOR_DIR/resource_snap.sh"
bash "$COLLECTOR_DIR/claude_monitor.sh"
bash "$COLLECTOR_DIR/docker_status.sh"

python3 "$COLLECTOR_DIR/hook_monitor.py"
python3 "$COLLECTOR_DIR/secrets_scan.py"
python3 "$COLLECTOR_DIR/api_cost.py"

echo "--- Anomaly Detection ---"
python3 "${SCRIPT_DIR}/analyzer/anomaly_detect.py" || true

echo "=== Done ==="
