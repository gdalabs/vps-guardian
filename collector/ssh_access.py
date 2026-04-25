#!/usr/bin/env python3
"""SSH Access Log Collector — parses auth.log into SQLite"""

import json
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "access_log.db"
WHITELIST_PATH = BASE_DIR / "analyzer" / "whitelist.json"

# Patterns
RE_ACCEPTED = re.compile(
    r"^(\S+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(publickey|password)\s+for\s+(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)(?:.*?(SHA256:\S+))?"
)
RE_FAILED = re.compile(
    r"^(\S+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)"
)


def load_whitelist():
    if not WHITELIST_PATH.exists():
        return set()
    with open(WHITELIST_PATH) as f:
        data = json.load(f)
    ips = set()
    for key, group in data.items():
        if isinstance(group, dict) and key != "notes":
            ips.update(group.keys())
    return ips


def parse_ts(ts_str):
    """Convert syslog ISO timestamp to UTC ISO string."""
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def get_last_ts(conn):
    row = conn.execute(
        "SELECT last_timestamp FROM collector_state WHERE collector_name='ssh'"
    ).fetchone()
    return row[0] if row and row[0] else "1970-01-01T00:00:00Z"


def main():
    conn = sqlite3.connect(str(DB_PATH))
    whitelist_ips = load_whitelist()
    last_ts = get_last_ts(conn)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Read auth.log via sudo
    try:
        result = subprocess.run(
            ["sudo", "cat", "/var/log/auth.log"],
            capture_output=True, text=True, timeout=30
        )
        lines = result.stdout.splitlines()
    except Exception as e:
        print(f"[ssh_access] Error reading auth.log: {e}")
        return

    insert_count = 0
    batch = []

    for line in lines:
        # Try accepted login
        m = RE_ACCEPTED.match(line)
        if m:
            ts_utc = parse_ts(m.group(1))
            if not ts_utc or ts_utc <= last_ts:
                continue
            method, user, ip, port = m.group(2), m.group(3), m.group(4), m.group(5)
            key_fp = m.group(6) or ""
            wl = 1 if ip in whitelist_ips else 0
            detail = json.dumps({"auth_method": method, "port": int(port), "key_fingerprint": key_fp})
            batch.append((ts_utc, "ssh", "login", ip, user, detail, wl))
            insert_count += 1
            continue

        # Try failed login (skip "message repeated" lines)
        if "message repeated" in line:
            continue
        m = RE_FAILED.match(line)
        if m:
            ts_utc = parse_ts(m.group(1))
            if not ts_utc or ts_utc <= last_ts:
                continue
            user, ip, port = m.group(2), m.group(3), m.group(4)
            wl = 1 if ip in whitelist_ips else 0
            invalid = 1 if "invalid user" in line else 0
            detail = json.dumps({"port": int(port), "invalid_user": invalid})
            batch.append((ts_utc, "ssh", "failed", ip, user, detail, wl))
            insert_count += 1

    # Bulk insert
    conn.executemany(
        "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        batch,
    )

    conn.execute(
        "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) "
        "VALUES ('ssh', ?, ?)",
        (now_utc, json.dumps({"insert_count": insert_count})),
    )
    conn.commit()
    conn.close()

    print(f"[ssh_access] {insert_count} events inserted (since {last_ts})")


if __name__ == "__main__":
    main()
