#!/usr/bin/env python3
"""Secrets Scanner — detects hardcoded tokens/keys in config files.

Scans Claude Code settings, shell profiles, and project configs for
patterns like GitHub PATs, Cloudflare tokens, API keys, and PII strings.
"""

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "access_log.db"

# Token/secret patterns
PATTERNS = {
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{36,}"),
    "github_token_classic": re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    "github_oauth": re.compile(r"gho_[A-Za-z0-9]{36,}"),
    "github_app": re.compile(r"ghu_[A-Za-z0-9]{36,}"),
    "github_refresh": re.compile(r"ghr_[A-Za-z0-9]{36,}"),
    "cloudflare_api_token": re.compile(r"cfat_[A-Za-z0-9_-]{30,}"),
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{40,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "telegram_bot_token": re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    "private_key_header": re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
}

# PII patterns — add your own strings to detect in project files
# Example: {"pii_myname": re.compile(r"\bmyname\b", re.IGNORECASE)}
PII_PATTERNS = {}

# Files/dirs to scan
SCAN_TARGETS = [
    # Claude Code settings (the original issue)
    Path.home() / ".claude",
    # Shell profiles
    Path.home() / ".bashrc",
    Path.home() / ".bash_profile",
    Path.home() / ".profile",
    Path.home() / ".zshrc",
    Path.home() / ".zshenv",
    # Project configs
    Path.home() / "projects",
]

# File extensions to check
SCAN_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".conf", ".cfg",
    ".env", ".sh", ".bash", ".zsh", ".py", ".js", ".ts",
    ".md", ".txt", ".ini",
}

# Skip these directories
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".pytest_cache", "dist", "build", ".wrangler", ".cache",
    "data",  # skip VPS Guardian's own DB dir
}

# Skip these files (expected to contain tokens by design)
SKIP_FILES = {
    ".env",           # gitignored, local only
    ".env.local",
    ".dev.vars",      # wrangler local dev
    ".credentials.json",  # Claude CLI managed
}

# Skip these absolute paths (local-only, not committed)
SKIP_PATHS = {
    Path.home() / ".zshrc",
    Path.home() / ".bashrc",
    Path.home() / ".bash_profile",
    Path.home() / ".profile",
    Path.home() / ".zshenv",
}

# Skip files that describe the policy itself (contain PII strings as examples)
POLICY_FILES = {"CLAUDE.md"}

# Max file size to scan (512KB)
MAX_FILE_SIZE = 512 * 1024


def should_scan(filepath: Path) -> bool:
    """Check if file should be scanned."""
    if filepath.name in SKIP_FILES:
        return False
    if filepath.resolve() in SKIP_PATHS:
        return False
    if any(part in SKIP_DIRS for part in filepath.parts):
        return False
    if filepath.suffix not in SCAN_EXTENSIONS and filepath.name not in {
        ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv",
    }:
        return False
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE:
            return False
    except OSError:
        return False
    return True


def scan_file(filepath: Path) -> list[dict]:
    """Scan a single file for secrets and PII."""
    findings = []
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for line_num, line in enumerate(text.splitlines(), 1):
        # Token patterns
        for secret_type, pattern in PATTERNS.items():
            for match in pattern.finditer(line):
                token = match.group()
                # Mask the token: show first 8 and last 4 chars
                if len(token) > 16:
                    masked = token[:8] + "..." + token[-4:]
                else:
                    masked = token[:4] + "..."
                findings.append({
                    "type": secret_type,
                    "file": str(filepath),
                    "line": line_num,
                    "masked": masked,
                })

        # PII patterns (only in project files, skip policy docs)
        if "projects" in filepath.parts and filepath.name not in POLICY_FILES:
            for pii_type, pattern in PII_PATTERNS.items():
                if pattern.search(line):
                    findings.append({
                        "type": pii_type,
                        "file": str(filepath),
                        "line": line_num,
                        "masked": line.strip()[:80],
                    })

    return findings


def main():
    conn = sqlite3.connect(str(DB_PATH))
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    all_findings: list[dict] = []
    files_scanned = 0

    for target in SCAN_TARGETS:
        if not target.exists():
            continue

        if target.is_file():
            files = [target]
        else:
            files = [f for f in target.rglob("*") if f.is_file()]

        for filepath in files:
            if not should_scan(filepath):
                continue
            files_scanned += 1
            findings = scan_file(filepath)
            all_findings.extend(findings)

    # Deduplicate by (type, file, line) — avoid repeated alerts
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f["type"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Insert findings
    for finding in unique_findings:
        detail = json.dumps(finding)

        conn.execute(
            "INSERT INTO access_log (timestamp, channel, event_type, source_ip, username, detail, is_whitelisted) "
            "VALUES (?, 'secrets_scan', 'secret_found', 'local', 'scanner', ?, 0)",
            (now_utc, detail),
        )

        severity = "critical" if not finding["type"].startswith("pii_") else "warning"
        category = "secrets_exposed" if not finding["type"].startswith("pii_") else "pii_leak"
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, category, message, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (now_utc, severity, category,
             f"{finding['type']} in {Path(finding['file']).name}:{finding['line']}",
             detail),
        )

    # Update collector state
    conn.execute(
        "INSERT OR REPLACE INTO collector_state (collector_name, last_timestamp, detail) "
        "VALUES ('secrets_scan', ?, ?)",
        (now_utc, json.dumps({
            "files_scanned": files_scanned,
            "secrets_found": len(unique_findings),
        })),
    )
    conn.commit()
    conn.close()

    print(f"[secrets_scan] {len(unique_findings)} findings in {files_scanned} files")


if __name__ == "__main__":
    main()
