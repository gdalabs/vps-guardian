#!/usr/bin/env bash
# VPS Guardian — One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/gdalabs/vps-guardian/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/gdalabs/vps-guardian.git"
INSTALL_DIR="${GUARDIAN_DIR:-$HOME/vps-guardian}"
BIND="${GUARDIAN_BIND:-127.0.0.1}"
PORT="${GUARDIAN_PORT:-8888}"

echo "=== VPS Guardian Installer ==="
echo ""

# --- Dependencies check ---
missing=()
for cmd in sqlite3 python3 bash; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: Missing required commands: ${missing[*]}"
    echo "Install them first (e.g. sudo apt install sqlite3 python3)"
    exit 1
fi

# --- Clone or update ---
if [[ -d "$INSTALL_DIR/.git" ]]; then
    echo "[1/5] Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull --ff-only
else
    echo "[1/5] Cloning repository..."
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# --- Initialize database ---
echo "[2/5] Initializing database..."
bash init_db.sh
# Enable WAL mode for concurrent read/write
sqlite3 data/access_log.db "PRAGMA journal_mode=WAL;" > /dev/null

# --- Whitelist setup ---
if [[ ! -f analyzer/whitelist.json ]]; then
    echo "[3/5] Creating whitelist from template..."
    cp analyzer/whitelist.example.json analyzer/whitelist.json
    echo "  -> Edit analyzer/whitelist.json with your known IPs"
else
    echo "[3/5] Whitelist already exists, skipping."
fi

# --- Cron setup ---
echo "[4/5] Setting up cron (every 5 minutes)..."
CRON_LINE="*/5 * * * * $INSTALL_DIR/run_all.sh >> $INSTALL_DIR/data/cron.log 2>&1"
# Remove old guardian cron entries, add new one
(crontab -l 2>/dev/null | grep -v "vps-guardian\|run_all\.sh" || true; echo "$CRON_LINE") | crontab -
echo "  -> Cron installed: $CRON_LINE"

# --- Run initial collection ---
echo "[5/5] Running initial data collection..."
bash run_all.sh 2>/dev/null || true

echo ""
echo "=== Installation complete ==="
echo ""
echo "Start the dashboard:"
echo "  GUARDIAN_BIND=$BIND GUARDIAN_PORT=$PORT nohup python3 $INSTALL_DIR/dashboard/server.py &"
echo ""
echo "Dashboard URL: http://$BIND:$PORT"
echo ""
echo "Next steps:"
echo "  1. Edit analyzer/whitelist.json with your known IPs"
echo "  2. (Optional) Set GUARDIAN_BIND to your Tailscale IP for private access"
echo "  3. (Optional) Install fail2ban: sudo apt install fail2ban"
echo ""
