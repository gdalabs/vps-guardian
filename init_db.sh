#!/usr/bin/env bash
# Initialize VPS Guardian SQLite database
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/data/access_log.db"

mkdir -p "$(dirname "$DB_PATH")"

sqlite3 "$DB_PATH" <<'SQL'
-- Access events: SSH, VS Code Tunnel, Tailscale, etc.
CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,           -- ISO 8601 UTC
    channel TEXT NOT NULL,             -- ssh, vscode_tunnel, tailscale
    event_type TEXT NOT NULL,          -- login, logout, failed, connection, disconnection
    source_ip TEXT,
    username TEXT,
    detail TEXT,                       -- JSON: auth method, tty, device name, etc.
    is_whitelisted INTEGER DEFAULT 0,  -- 1=known, 0=unknown
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_access_timestamp ON access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_channel ON access_log(channel);
CREATE INDEX IF NOT EXISTS idx_access_source_ip ON access_log(source_ip);
CREATE INDEX IF NOT EXISTS idx_access_whitelisted ON access_log(is_whitelisted);

-- Resource snapshots (time-series)
CREATE TABLE IF NOT EXISTS resource_snapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    cpu_percent REAL,
    mem_total_mb INTEGER,
    mem_used_mb INTEGER,
    mem_available_mb INTEGER,
    swap_total_mb INTEGER,
    swap_used_mb INTEGER,
    disk_total_gb REAL,
    disk_used_gb REAL,
    disk_avail_gb REAL,
    net_rx_bytes INTEGER,
    net_tx_bytes INTEGER,
    load_1 REAL,
    load_5 REAL,
    load_15 REAL
);

CREATE INDEX IF NOT EXISTS idx_resource_timestamp ON resource_snapshot(timestamp);

-- Claude Code instances
CREATE TABLE IF NOT EXISTS claude_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    username TEXT,
    tty TEXT,
    mem_rss_kb INTEGER,
    cpu_percent REAL,
    start_time TEXT,
    elapsed TEXT,
    work_dir TEXT,
    project_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_claude_timestamp ON claude_instances(timestamp);

-- Service status
CREATE TABLE IF NOT EXISTS service_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    service_name TEXT NOT NULL,
    service_type TEXT NOT NULL,        -- systemd, docker, process
    status TEXT NOT NULL,              -- running, stopped, exited, etc.
    detail TEXT                        -- JSON: ports, image, uptime, etc.
);

CREATE INDEX IF NOT EXISTS idx_service_timestamp ON service_status(timestamp);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,            -- info, warning, critical
    category TEXT NOT NULL,            -- unknown_ip, brute_force, service_down, etc.
    message TEXT NOT NULL,
    detail TEXT,
    acknowledged INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

-- Metadata: track last processed log position
CREATE TABLE IF NOT EXISTS collector_state (
    collector_name TEXT PRIMARY KEY,
    last_timestamp TEXT,
    last_offset INTEGER,
    detail TEXT
);
SQL

echo "Database initialized: $DB_PATH"
