#!/usr/bin/env python3
"""Claude Code Hook Block Monitor — detects BLOCKED events from session logs"""

import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "access_log.db"
MARKER = Path("/tmp/.guardian_hook_marker")
CLAUDE_PROJECTS = Path.home() / ".claude" / "projects"


def get_marker_time():
    if MARKER.exists():
        return MARKER.stat().st_mtime
    return 0


def scan_hook_blocks(conn):
    """Scan Claude Code JSONL logs for actual hook block events."""
    marker_time = get_marker_time()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    insert_count = 0

    if not CLAUDE_PROJECTS.exists():
        return insert_count

    for jsonl_file in CLAUDE_PROJECTS.rglob("*.jsonl"):
        if jsonl_file.stat().st_mtime <= marker_time:
            continue

        try:
            with open(jsonl_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Look for hook block results in tool results
                    # These appear as error messages with "BLOCKED" from hooks
                    msg = data.get("message", {})
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        content = " ".join(
                            str(c.get("content", "") if isinstance(c, dict) else c)
                            for c in content
                        )

                    # Only match actual block events (stderr output from hooks),
                    # not hook configuration being read
                    if "BLOCKED" not in str(content):
                        continue

                    # Skip if this is a settings.json read (hook config, not block event)
                    if "settings.json" in str(data.get("toolUseResult", {}).get("file", {}).get("filePath", "")):
                        continue
                    # Skip if type is 'user' reading a file containing hook config
                    if data.get("type") == "user":
                        tool_result = data.get("toolUseResult", {})
                        if isinstance(tool_result, dict) and tool_result.get("file"):
                            continue

                    # Look for actual hook execution results
                    # Hook blocks appear in hookResults or as tool errors
                    hook_results = data.get("hookResults", [])
                    for hr in hook_results if isinstance(hook_results, list) else []:
                        stderr = hr.get("stderr", "")
                        if "BLOCKED" in stderr:
                            reason = stderr.strip()
                            ts = data.get("timestamp", now_utc)
                            session_id = str(jsonl_file.stem)
                            detail = json.dumps({
                                "reason": reason,
                                "session": session_id,
                                "hook": hr.get("hookCommand", ""),
                            })
                            conn.execute(
                                "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) "
                                "VALUES (?, 'claude_hook', 'blocked', 'local', 'claude', ?, 1)",
                                (ts, detail),
                            )
                            insert_count += 1

        except Exception:
            continue

    conn.commit()
    return insert_count


def scan_gitleaks(conn, full=False):
    """Run gitleaks on projects (only if --full)."""
    if not full:
        return 0

    try:
        subprocess.run(["gitleaks", "version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return 0

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    alert_count = 0
    projects_dir = Path.home() / "projects"

    for proj_dir in projects_dir.iterdir():
        if not (proj_dir / ".git").is_dir():
            continue
        proj_name = proj_dir.name
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--no-banner", "--no-color", "-f", "json"],
                cwd=str(proj_dir),
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 1:  # leaks found
                try:
                    leaks = json.loads(result.stdout)
                    leak_count = len(leaks) if isinstance(leaks, list) else 0
                except json.JSONDecodeError:
                    leak_count = 1
                detail = json.dumps({"project": proj_name, "leaks_found": leak_count})
                conn.execute(
                    "INSERT INTO alerts (timestamp, severity, category, message, detail) "
                    "VALUES (?, 'warning', 'gitleaks', ?, ?)",
                    (now_utc, f"Secrets detected in {proj_name}: {leak_count} leaks", detail),
                )
                alert_count += 1
        except Exception:
            continue

    conn.commit()
    return alert_count


def main():
    import sys
    full = "--full" in sys.argv

    conn = sqlite3.connect(str(DB_PATH))
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    hook_count = scan_hook_blocks(conn)
    gitleaks_count = scan_gitleaks(conn, full)

    # Update marker
    MARKER.touch()

    conn.execute(
        "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) "
        "VALUES ('hook_monitor', ?, ?)",
        (now_utc, json.dumps({"hook_blocks": hook_count, "gitleaks_alerts": gitleaks_count})),
    )
    conn.commit()
    conn.close()

    print(f"[hook_monitor] {hook_count} hook blocks, {gitleaks_count} gitleaks alerts")


if __name__ == "__main__":
    main()
