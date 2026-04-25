#!/usr/bin/env python3
"""VPS Guardian Dashboard API Server — Tailscale-only bind"""

import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "access_log.db"
DASHBOARD_DIR = Path(__file__).resolve().parent
BIND_HOST = os.environ.get("GUARDIAN_BIND", "127.0.0.1")
PORT = int(os.environ.get("GUARDIAN_PORT", "8888"))


def get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 3000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def query_to_list(conn, sql, params=()):
    cur = conn.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


class GuardianHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path.startswith("/api/"):
            self.handle_api(path, qs)
        else:
            super().do_GET()

    def handle_api(self, path, qs):
        # QR code endpoint — returns SVG directly
        if path == "/api/qr":
            self._send_qr(qs)
            return

        conn = None
        try:
            conn = get_db()
            hours = int(qs.get("hours", ["24"])[0])
            limit = int(qs.get("limit", ["200"])[0])

            if path == "/api/resources":
                data = query_to_list(conn,
                    "SELECT * FROM resource_snapshot ORDER BY timestamp DESC LIMIT ?", (limit,))
            elif path == "/api/resources/latest":
                data = query_to_list(conn,
                    "SELECT * FROM resource_snapshot ORDER BY timestamp DESC LIMIT 1")
            elif path == "/api/access":
                data = query_to_list(conn,
                    "SELECT * FROM access_log WHERE timestamp > datetime('now', ?) "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (f"-{hours} hours", limit))
            elif path == "/api/access/ssh":
                data = query_to_list(conn,
                    "SELECT * FROM access_log WHERE channel='ssh' AND timestamp > datetime('now', ?) "
                    "ORDER BY timestamp DESC LIMIT ?",
                    (f"-{hours} hours", limit))
            elif path == "/api/access/unknown":
                data = query_to_list(conn,
                    "SELECT * FROM access_log WHERE is_whitelisted=0 AND event_type='login' "
                    "ORDER BY timestamp DESC LIMIT ?", (limit,))
            elif path == "/api/access/failed/summary":
                data = query_to_list(conn,
                    "SELECT source_ip, COUNT(*) as count, MIN(timestamp) as first_seen, "
                    "MAX(timestamp) as last_seen FROM access_log "
                    "WHERE channel='ssh' AND event_type='failed' AND timestamp > datetime('now', ?) "
                    "GROUP BY source_ip ORDER BY count DESC LIMIT ?",
                    (f"-{hours} hours", limit))
            elif path == "/api/claude":
                data = query_to_list(conn,
                    "SELECT * FROM claude_instances WHERE timestamp = "
                    "(SELECT MAX(timestamp) FROM claude_instances)")
            elif path == "/api/services":
                data = query_to_list(conn,
                    "SELECT * FROM service_status WHERE timestamp = "
                    "(SELECT MAX(timestamp) FROM service_status)")
            elif path == "/api/alerts":
                data = query_to_list(conn,
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
            elif path == "/api/alerts/active":
                data = query_to_list(conn,
                    "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY timestamp DESC LIMIT ?",
                    (limit,))
            elif path == "/api/hooks":
                data = query_to_list(conn,
                    "SELECT * FROM access_log WHERE channel='claude_hook' "
                    "ORDER BY timestamp DESC LIMIT ?", (limit,))
            elif path == "/api/cost":
                data = self._get_cost(conn, qs)
            elif path == "/api/cost/summary":
                data = self._get_cost_summary(conn)
            elif path == "/api/fail2ban":
                data = self._get_fail2ban()
            elif path == "/api/stats":
                data = self._get_stats(conn, hours)
            elif path == "/api/live":
                data = self._get_live_status(conn)
            else:
                self._send_json({"error": "Unknown endpoint"}, 404)
                return

            self._send_json(data)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
        finally:
            if conn:
                conn.close()

    def _get_stats(self, conn, hours):
        since = f"-{hours} hours"
        total_logins = conn.execute(
            "SELECT COUNT(*) FROM access_log WHERE channel='ssh' AND event_type='login' AND timestamp > datetime('now', ?)",
            (since,)).fetchone()[0]
        total_failed = conn.execute(
            "SELECT COUNT(*) FROM access_log WHERE channel='ssh' AND event_type='failed' AND timestamp > datetime('now', ?)",
            (since,)).fetchone()[0]
        unknown_logins = conn.execute(
            "SELECT COUNT(*) FROM access_log WHERE is_whitelisted=0 AND event_type='login' AND timestamp > datetime('now', ?)",
            (since,)).fetchone()[0]
        active_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        hook_blocks = conn.execute(
            "SELECT COUNT(*) FROM access_log WHERE channel='claude_hook' AND timestamp > datetime('now', ?)",
            (since,)).fetchone()[0]
        unique_attackers = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM access_log WHERE channel='ssh' AND event_type='failed' AND is_whitelisted=0 AND timestamp > datetime('now', ?)",
            (since,)).fetchone()[0]
        return {
            "period_hours": hours,
            "ssh_logins": total_logins,
            "ssh_failed": total_failed,
            "unknown_ip_logins": unknown_logins,
            "active_alerts": active_alerts,
            "hook_blocks": hook_blocks,
            "unique_attackers": unique_attackers,
        }

    def _get_live_status(self, conn):
        # Real-time system info
        try:
            ts_status = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True, text=True, timeout=5
            )
            tailscale = json.loads(ts_status.stdout) if ts_status.returncode == 0 else {}
        except Exception:
            tailscale = {}

        resource = query_to_list(conn,
            "SELECT * FROM resource_snapshot ORDER BY timestamp DESC LIMIT 1")
        claude = query_to_list(conn,
            "SELECT * FROM claude_instances WHERE timestamp = "
            "(SELECT MAX(timestamp) FROM claude_instances)")
        services = query_to_list(conn,
            "SELECT * FROM service_status WHERE timestamp = "
            "(SELECT MAX(timestamp) FROM service_status)")

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "resource": resource[0] if resource else {},
            "claude_instances": claude,
            "services": services,
            "tailscale_peers": len(tailscale.get("Peer", {})) if isinstance(tailscale.get("Peer"), dict) else 0,
        }

    def _get_fail2ban(self):
        try:
            result = subprocess.run(
                ["sudo", "fail2ban-client", "status", "sshd"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            import re
            currently_banned = int(re.search(r"Currently banned:\s+(\d+)", output).group(1)) if re.search(r"Currently banned:\s+(\d+)", output) else 0
            total_banned = int(re.search(r"Total banned:\s+(\d+)", output).group(1)) if re.search(r"Total banned:\s+(\d+)", output) else 0
            currently_failed = int(re.search(r"Currently failed:\s+(\d+)", output).group(1)) if re.search(r"Currently failed:\s+(\d+)", output) else 0
            banned_ips = re.search(r"Banned IP list:\s+(.*)", output)
            banned_list = banned_ips.group(1).split() if banned_ips else []
            return {
                "currently_banned": currently_banned,
                "total_banned": total_banned,
                "currently_failed": currently_failed,
                "banned_ips": banned_list,
            }
        except Exception as e:
            return {"error": str(e), "currently_banned": 0, "total_banned": 0, "banned_ips": []}

    def _get_cost(self, conn, qs):
        days = int(qs.get("days", ["7"])[0])
        group = qs.get("group", ["date"])[0]  # date, model, project
        valid_groups = {"date", "model", "project"}
        if group not in valid_groups:
            group = "date"
        return query_to_list(conn,
            f"SELECT {group}, SUM(input_tokens) as input_tokens, "
            f"SUM(output_tokens) as output_tokens, "
            f"SUM(cache_read_tokens) as cache_read_tokens, "
            f"SUM(cache_create_tokens) as cache_create_tokens, "
            f"SUM(cost_usd) as cost_usd, SUM(message_count) as messages "
            f"FROM api_cost WHERE date >= date('now', ?) "
            f"GROUP BY {group} ORDER BY {group} DESC",
            (f"-{days} days",))

    def _get_cost_summary(self, conn):
        row = conn.execute(
            "SELECT SUM(cost_usd), SUM(input_tokens), SUM(output_tokens), "
            "SUM(cache_read_tokens), SUM(cache_create_tokens), SUM(message_count) "
            "FROM api_cost"
        ).fetchone()
        today = conn.execute(
            "SELECT SUM(cost_usd) FROM api_cost WHERE date = date('now')"
        ).fetchone()
        week = conn.execute(
            "SELECT SUM(cost_usd) FROM api_cost WHERE date >= date('now', '-7 days')"
        ).fetchone()
        month = conn.execute(
            "SELECT SUM(cost_usd) FROM api_cost WHERE date >= date('now', '-30 days')"
        ).fetchone()
        return {
            "total_cost": round(row[0] or 0, 2),
            "total_input_tokens": row[1] or 0,
            "total_output_tokens": row[2] or 0,
            "total_cache_read_tokens": row[3] or 0,
            "total_cache_create_tokens": row[4] or 0,
            "total_messages": row[5] or 0,
            "today_cost": round(today[0] or 0, 2),
            "week_cost": round(week[0] or 0, 2),
            "month_cost": round(month[0] or 0, 2),
        }

    def _send_qr(self, qs):
        import io
        try:
            import qrcode
            import qrcode.image.svg
        except ImportError:
            self._send_json({"error": "qrcode module not installed"}, 500)
            return
        url = qs.get("url", [f"http://{BIND_HOST}:{PORT}"])[0]
        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(url, image_factory=factory, box_size=10, border=2)
        buf = io.BytesIO()
        img.save(buf)
        body = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress routine logs
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    server = ThreadedHTTPServer((BIND_HOST, PORT), GuardianHandler)
    print(f"VPS Guardian Dashboard: http://{BIND_HOST}:{PORT}")
    print("Tailscale-only access. Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()
