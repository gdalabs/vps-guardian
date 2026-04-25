#!/usr/bin/env python3
"""VPS Guardian — Anomaly Detection & Alert Generator"""

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "access_log.db"
WHITELIST_PATH = BASE_DIR / "analyzer" / "whitelist.json"


def load_whitelist():
    with open(WHITELIST_PATH) as f:
        data = json.load(f)
    ips = set()
    for group_name, group in data.items():
        if isinstance(group, dict) and group_name != "notes":
            ips.update(group.keys())
    return ips


def check_unknown_ips(conn, whitelist_ips, since_hours=24):
    """Find successful SSH logins from non-whitelisted IPs."""
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    cur = conn.execute(
        "SELECT timestamp, source_ip, username, detail FROM access_log "
        "WHERE channel='ssh' AND event_type='login' AND timestamp > ? "
        "ORDER BY timestamp DESC",
        (since,),
    )
    alerts = []
    for row in cur:
        ts, ip, user, detail = row
        if ip and ip not in whitelist_ips:
            alerts.append({
                "severity": "critical",
                "category": "unknown_ip",
                "message": f"SSH login from unknown IP: {ip} as {user}",
                "detail": json.dumps({"timestamp": ts, "ip": ip, "user": user, "auth": detail}),
            })
    return alerts


def check_brute_force(conn, threshold=20, window_minutes=10):
    """Detect brute-force attempts: >threshold failures in window."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    cur = conn.execute(
        "SELECT source_ip, COUNT(*) as cnt FROM access_log "
        "WHERE channel='ssh' AND event_type='failed' AND timestamp > ? "
        "GROUP BY source_ip HAVING cnt >= ? "
        "ORDER BY cnt DESC",
        (since, threshold),
    )
    alerts = []
    for ip, cnt in cur:
        alerts.append({
            "severity": "warning",
            "category": "brute_force",
            "message": f"Brute-force attempt: {cnt} failed logins from {ip} in {window_minutes}min",
            "detail": json.dumps({"ip": ip, "count": cnt, "window_minutes": window_minutes}),
        })
    return alerts


def check_service_down(conn):
    """Check if critical services are down in latest snapshot."""
    cur = conn.execute(
        "SELECT service_name, status, detail FROM service_status "
        "WHERE timestamp = (SELECT MAX(timestamp) FROM service_status) "
        "AND service_type = 'systemd' AND status != 'active'"
    )
    alerts = []
    critical_services = {"ssh", "tailscaled", "docker"}
    for name, status, detail in cur:
        if name in critical_services:
            alerts.append({
                "severity": "critical",
                "category": "service_down",
                "message": f"Critical service {name} is {status}",
                "detail": detail or "{}",
            })
    return alerts


def check_high_resource(conn, cpu_threshold=90, mem_threshold=90, disk_threshold=85):
    """Check resource usage thresholds."""
    cur = conn.execute(
        "SELECT cpu_percent, mem_total_mb, mem_used_mb, disk_total_gb, disk_used_gb "
        "FROM resource_snapshot ORDER BY timestamp DESC LIMIT 1"
    )
    row = cur.fetchone()
    if not row:
        return []
    cpu, mem_total, mem_used, disk_total, disk_used = row
    alerts = []
    if cpu and cpu > cpu_threshold:
        alerts.append({
            "severity": "warning",
            "category": "high_cpu",
            "message": f"CPU usage {cpu:.1f}% exceeds {cpu_threshold}%",
            "detail": json.dumps({"cpu_percent": cpu}),
        })
    if mem_total and mem_used:
        mem_pct = (mem_used / mem_total) * 100
        if mem_pct > mem_threshold:
            alerts.append({
                "severity": "warning",
                "category": "high_memory",
                "message": f"Memory usage {mem_pct:.1f}% exceeds {mem_threshold}%",
                "detail": json.dumps({"mem_used_mb": mem_used, "mem_total_mb": mem_total}),
            })
    if disk_total and disk_used:
        disk_pct = (disk_used / disk_total) * 100
        if disk_pct > disk_threshold:
            alerts.append({
                "severity": "warning",
                "category": "high_disk",
                "message": f"Disk usage {disk_pct:.1f}% exceeds {disk_threshold}%",
                "detail": json.dumps({"disk_used_gb": disk_used, "disk_total_gb": disk_total}),
            })
    return alerts


def save_alerts(conn, alerts):
    now = datetime.now(timezone.utc).isoformat()
    for a in alerts:
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, category, message, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (now, a["severity"], a["category"], a["message"], a["detail"]),
        )
    conn.commit()


def main():
    conn = sqlite3.connect(str(DB_PATH))
    whitelist_ips = load_whitelist()

    all_alerts = []
    all_alerts.extend(check_unknown_ips(conn, whitelist_ips))
    all_alerts.extend(check_brute_force(conn))
    all_alerts.extend(check_service_down(conn))
    all_alerts.extend(check_high_resource(conn))

    if all_alerts:
        save_alerts(conn, all_alerts)
        for a in all_alerts:
            icon = {"critical": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(a["severity"], "•")
            print(f"{icon} [{a['severity'].upper()}] {a['message']}")
    else:
        print("✅ No anomalies detected")

    conn.close()
    return 1 if any(a["severity"] == "critical" for a in all_alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
