#!/usr/bin/env python3
"""Claude API Cost Calculator — extracts token usage from session logs and calculates cost"""

import json
import sqlite3
import glob
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "access_log.db"
SESSIONS_DIR = Path.home() / ".claude" / "projects"

# Anthropic pricing (USD per 1M tokens) — May 2025
# https://docs.anthropic.com/en/docs/about-claude/models
PRICING = {
    "claude-opus-4-6": {
        "input": 15.0,
        "output": 75.0,
        "cache_read": 1.5,       # 90% discount
        "cache_create": 18.75,   # 25% premium
    },
    "claude-sonnet-4-6": {
        "input": 3.0,
        "output": 15.0,
        "cache_read": 0.30,
        "cache_create": 3.75,
    },
    "claude-haiku-4-5-20251001": {
        "input": 0.80,
        "output": 4.0,
        "cache_read": 0.08,
        "cache_create": 1.0,
    },
}

# Fallback for unknown models
DEFAULT_PRICING = {
    "input": 15.0,
    "output": 75.0,
    "cache_read": 1.5,
    "cache_create": 18.75,
}


def ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_cost (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            date TEXT NOT NULL,
            model TEXT NOT NULL,
            session_id TEXT,
            project TEXT,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cache_read_tokens INTEGER DEFAULT 0,
            cache_create_tokens INTEGER DEFAULT 0,
            cost_usd REAL DEFAULT 0,
            message_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_apicost_date ON api_cost(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_apicost_model ON api_cost(model)")
    conn.commit()


def calc_cost(model, input_t, output_t, cache_read_t, cache_create_t):
    p = PRICING.get(model, DEFAULT_PRICING)
    cost = (
        (input_t / 1_000_000) * p["input"]
        + (output_t / 1_000_000) * p["output"]
        + (cache_read_t / 1_000_000) * p["cache_read"]
        + (cache_create_t / 1_000_000) * p["cache_create"]
    )
    return round(cost, 6)


def get_last_processed(conn):
    row = conn.execute(
        "SELECT last_timestamp FROM collector_state WHERE collector_name='api_cost'"
    ).fetchone()
    return row[0] if row and row[0] else "1970-01-01T00:00:00Z"


def extract_project(filepath):
    """Extract project name from session path."""
    name = Path(filepath).parent.name
    # Format: -home-USER-projects-PROJECT_NAME
    if "-projects-" in name:
        return name.split("-projects-")[-1]
    elif name.endswith(Path.home().name):
        return "(home)"
    return name


def main():
    conn = sqlite3.connect(str(DB_PATH))
    ensure_table(conn)

    last_ts = get_last_processed(conn)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    total_messages = 0
    total_cost = 0.0
    # Aggregate by (date, model, session, project)
    daily = defaultdict(lambda: {
        "input": 0, "output": 0, "cache_read": 0, "cache_create": 0, "count": 0
    })

    for jsonl_path in glob.glob(str(SESSIONS_DIR / "*" / "*.jsonl")):
        project = extract_project(jsonl_path)
        session_id = Path(jsonl_path).stem

        try:
            with open(jsonl_path) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if data.get("type") != "assistant":
                        continue

                    msg = data.get("message", {})
                    usage = msg.get("usage")
                    if not usage:
                        continue

                    ts = data.get("timestamp", "")
                    if not ts or ts <= last_ts:
                        continue

                    model = msg.get("model", "unknown")
                    date = ts[:10]  # YYYY-MM-DD

                    input_t = usage.get("input_tokens", 0)
                    output_t = usage.get("output_tokens", 0)
                    cache_read_t = usage.get("cache_read_input_tokens", 0)
                    cache_create_t = usage.get("cache_creation_input_tokens", 0)

                    key = (date, model, session_id, project)
                    daily[key]["input"] += input_t
                    daily[key]["output"] += output_t
                    daily[key]["cache_read"] += cache_read_t
                    daily[key]["cache_create"] += cache_create_t
                    daily[key]["count"] += 1
                    total_messages += 1

        except Exception:
            continue

    # Insert aggregated data
    for (date, model, session_id, project), d in daily.items():
        cost = calc_cost(model, d["input"], d["output"], d["cache_read"], d["cache_create"])
        total_cost += cost
        conn.execute(
            "INSERT INTO api_cost (timestamp, date, model, session_id, project, "
            "input_tokens, output_tokens, cache_read_tokens, cache_create_tokens, "
            "cost_usd, message_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now_utc, date, model, session_id, project,
             d["input"], d["output"], d["cache_read"], d["cache_create"],
             cost, d["count"]),
        )

    conn.execute(
        "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) "
        "VALUES ('api_cost', ?, ?)",
        (now_utc, json.dumps({"messages": total_messages, "cost_usd": total_cost})),
    )
    conn.commit()
    conn.close()

    print(f"[api_cost] {total_messages} messages, ${total_cost:.4f} USD")


if __name__ == "__main__":
    main()
