# VPS Guardian

24-hour VPS monitoring system — access logs, resource usage, security posture, and Claude Code activity on a single dashboard.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

## What it does

- **Access log collection** — SSH, VS Code Tunnel, Tailscale connections tracked and classified
- **Anomaly detection** — Unknown IP login alerts, brute-force detection, service-down monitoring
- **Resource monitoring** — CPU, memory, disk, swap, load average (5-min snapshots)
- **Service inventory** — systemd services, Docker containers, listening ports with exposure classification (public / Tailscale / localhost)
- **Claude Code monitor** — Running instances, memory/CPU per project
- **API cost tracking** — Claude API token usage and cost breakdown by project/day
- **Security posture** — fail2ban status, public port audit, SSH config checks
- **Secrets scanner** — Detects hardcoded tokens/keys in config files
- **Web dashboard** — Light/dark theme, auto-refresh, mobile-friendly, QR code access

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/gdalabs/vps-guardian/main/install.sh | bash
```

This will:
1. Clone the repo to `~/vps-guardian`
2. Initialize the SQLite database
3. Set up a cron job (every 5 minutes)
4. Run the first data collection

Then start the dashboard:

```bash
cd ~/vps-guardian
python3 dashboard/server.py
# → http://127.0.0.1:8888
```

### Tailscale-only access (recommended)

```bash
GUARDIAN_BIND=100.x.x.x python3 dashboard/server.py
```

Replace `100.x.x.x` with your VPS's Tailscale IP.

## Configuration

### IP Whitelist

Edit `analyzer/whitelist.json` to define your known IPs:

```json
{
  "tailscale": {
    "100.x.x.x": "my-vps (self)",
    "100.x.x.x": "my-laptop"
  },
  "known_public": {
    "203.0.113.1": "Home ISP"
  }
}
```

SSH logins from IPs not in this list trigger **Unknown IP** alerts.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_BIND` | `127.0.0.1` | Dashboard bind address |
| `GUARDIAN_PORT` | `8888` | Dashboard port |
| `GUARDIAN_DIR` | `~/vps-guardian` | Install directory (for installer) |

### PII Scanner

Add custom strings to detect in `collector/secrets_scan.py`:

```python
PII_PATTERNS = {
    "pii_myname": re.compile(r"\bmyname\b", re.IGNORECASE),
}
```

## Architecture

```
vps-guardian/
├── collector/           # Data collection scripts (bash + python)
│   ├── ssh_access.py    # SSH auth.log parser
│   ├── tailscale_log.sh # Tailscale peer snapshots
│   ├── vscode_tunnel.sh # VS Code tunnel detector
│   ├── resource_snap.sh # CPU/Mem/Disk/Net/Load
│   ├── claude_monitor.sh# Claude Code instance tracker
│   ├── docker_status.sh # Docker + systemd + ports
│   ├── hook_monitor.py  # Claude hook block detector
│   ├── secrets_scan.py  # Token/key/PII scanner
│   └── api_cost.py      # Claude API cost calculator
├── analyzer/
│   ├── whitelist.json   # Your known IPs (gitignored)
│   └── anomaly_detect.py# Anomaly detection rules
├── dashboard/
│   ├── index.html       # Single-page dashboard
│   ├── style.css        # Light/dark theme
│   ├── app.js           # Client-side logic
│   └── server.py        # API server (threaded)
├── data/
│   └── access_log.db    # SQLite database (gitignored)
├── install.sh           # One-line installer
├── init_db.sh           # Database schema
└── run_all.sh           # Collector orchestrator
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Collector | Bash + Python 3 |
| Storage | SQLite (WAL mode) |
| Analyzer | Python 3 |
| Dashboard | Vanilla HTML/CSS/JS |
| Server | Python `http.server` (threaded) |
| Scheduling | cron (5-min interval) |

### Dashboard API

| Endpoint | Description |
|----------|-------------|
| `GET /api/resources/latest` | Latest CPU/Mem/Disk snapshot |
| `GET /api/access?hours=24` | Access log entries |
| `GET /api/access/ssh` | SSH events only |
| `GET /api/access/failed/summary` | Failed login IPs ranked by count |
| `GET /api/access/unknown` | Logins from non-whitelisted IPs |
| `GET /api/claude` | Active Claude Code instances |
| `GET /api/services` | systemd + Docker + port status |
| `GET /api/alerts` | All alerts |
| `GET /api/alerts/active` | Unacknowledged alerts |
| `GET /api/cost/summary` | API cost totals |
| `GET /api/cost?days=7&group=date` | Cost breakdown (group: date/model/project) |
| `GET /api/fail2ban` | fail2ban status |
| `GET /api/stats` | Summary statistics |
| `GET /api/live` | Real-time system status |
| `GET /api/qr` | Dashboard QR code (SVG) |

## Security Recommendations

After installation:

1. **Edit whitelist** — Add your Tailscale IPs and home ISP to `analyzer/whitelist.json`
2. **Enable fail2ban** — `sudo apt install fail2ban` (auto-detected by dashboard)
3. **Bind to Tailscale** — Set `GUARDIAN_BIND` to your Tailscale IP
4. **SSH hardening** — Disable password auth: `PasswordAuthentication no` in `/etc/ssh/sshd_config`
5. **UFW** — Enable firewall: `sudo ufw allow 22/tcp && sudo ufw allow 41641/udp && sudo ufw enable`

## Requirements

- Linux (Ubuntu 22.04+ recommended)
- Python 3.8+
- SQLite 3
- `sudo` access for reading `/var/log/auth.log`
- Optional: Tailscale, Docker, fail2ban, Claude Code

## License

[MIT](LICENSE)
