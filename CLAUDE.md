# VPS Guardian

24-hour VPS monitoring: access logs, resource usage, security posture, and Claude Code activity.

## Mission

1. **Access log collection** — SSH, VS Code Tunnel, Tailscale connections recorded and classified
2. **Anomaly detection** — Unknown IP alerts, brute-force detection, service-down monitoring
3. **Dashboard** — Resources, services, Claude Code instances, security on one page
4. **Audit trail** — Who connected, from where, when, and what they did

## Architecture

```
vps-guardian/
├── collector/           # Bash + Python scripts (cron every 5 min)
├── analyzer/            # Anomaly detection, IP whitelist
├── dashboard/           # Vanilla HTML/JS + Python API server
├── data/                # SQLite DB + logs (gitignored)
├── install.sh           # One-line installer
├── init_db.sh           # DB schema
└── run_all.sh           # Collector orchestrator
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Collector | Bash + Python 3 (OS tools, no deps) |
| Storage | SQLite (WAL mode for concurrent access) |
| Dashboard | Vanilla HTML/CSS/JS, Python http.server (threaded) |
| Scheduling | cron |

## Key Design Decisions

- **SQLite WAL mode** — Prevents lock contention between cron writers and dashboard readers
- **ThreadingHTTPServer** — One slow request doesn't block the entire dashboard
- **busy_timeout = 3000ms** — Graceful retry on transient DB locks
- **Tailscale-only bind** — Dashboard never exposed to public internet
- **Zero npm/pip deps** — Runs on any Linux box with Python 3 and SQLite

## Commands

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/gdalabs/vps-guardian/main/install.sh | bash

# Manual collection run
bash run_all.sh

# Start dashboard
GUARDIAN_BIND=127.0.0.1 GUARDIAN_PORT=8888 python3 dashboard/server.py

# Query access log
sqlite3 data/access_log.db "SELECT * FROM access_log WHERE timestamp > datetime('now', '-24 hours');"
```

## Configuration

- `GUARDIAN_BIND` — Dashboard bind address (default: 127.0.0.1)
- `GUARDIAN_PORT` — Dashboard port (default: 8888)
- `analyzer/whitelist.json` — Known IP addresses (copy from whitelist.example.json)

## Conventions

- Timestamps stored in UTC, displayed in browser's local timezone (JST on dashboard)
- Dashboard bound to Tailscale IP only — never public
- SQLite DB is gitignored (contains personal access data)
- Scripts use relative paths via `$(dirname "$0")`
