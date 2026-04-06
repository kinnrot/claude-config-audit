"""
Core audit logic — shared between the SessionStart hook and the /audit skill hook.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import TypedDict

CLAUDE_DIR = Path.home() / ".claude"

# Known interpreter prefixes so we can isolate the path argument
_INTERPRETERS = {"python3", "python", "python3.11", "python3.12", "bash", "sh", "zsh", "node", "ruby", "perl"}

# Patterns that look like real secrets (not key names, actual values)
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                          # OpenAI-style
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),                         # GitHub PAT classic
    re.compile(r"github_pat_[A-Za-z0-9_]{50,}"),                 # GitHub fine-grained PAT
    re.compile(r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+"),             # Slack bot token
    re.compile(r"xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+"),     # Slack user token
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"vercel_[a-z0-9]{24,}", re.IGNORECASE),          # Vercel token
    re.compile(r"v1\.[a-zA-Z0-9_-]{40,}"),                       # Generic v1 token pattern
]


class Finding(TypedDict):
    severity: str   # HIGH | MEDIUM | LOW
    file: str
    issue: str
    fix: str


def _shorten(path: Path) -> str:
    """Replace home dir with ~ for display."""
    try:
        return "~/" + str(path.relative_to(Path.home()))
    except ValueError:
        return str(path)


def _extract_path_from_command(cmd: str) -> str:
    """
    Given a hook command string like 'python3 /some/path/hook.py'
    or '/some/path/hook.sh', return the file-system path argument.
    """
    parts = cmd.strip().split(None, 2)
    if not parts:
        return ""
    if parts[0] in _INTERPRETERS and len(parts) > 1:
        return parts[1]
    return parts[0]


def _is_relative_path(path_str: str) -> bool:
    """Return True if path_str looks like a relative file path (not absolute or variable)."""
    if not path_str:
        return False
    return not any(path_str.startswith(p) for p in ("/", "~", "${", "$"))


def _check_hook_commands(data: dict, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    hooks = data.get("hooks", {})
    for event, matchers in hooks.items():
        if not isinstance(matchers, list):
            continue
        for matcher_block in matchers:
            for hook in matcher_block.get("hooks", []):
                cmd = hook.get("command", "")
                if not cmd:
                    continue
                path_arg = _extract_path_from_command(cmd)
                if _is_relative_path(path_arg):
                    findings.append(Finding(
                        severity="MEDIUM",
                        file=rel,
                        issue=f"Relative hook path in `{event}` event: `{cmd[:100]}`",
                        fix="Use an absolute path or ${CLAUDE_PLUGIN_ROOT}/...",
                    ))
                elif path_arg.startswith("/") and not Path(path_arg.split()[0]).exists():
                    # Absolute path that doesn't exist on disk
                    findings.append(Finding(
                        severity="MEDIUM",
                        file=rel,
                        issue=f"Hook script not found on disk (`{event}`): `{path_arg}`",
                        fix="Verify the file exists or remove the hook entry",
                    ))
    return findings


def check_settings_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel = _shorten(path)

    # Stale backup file
    if path.name.endswith(".bak"):
        findings.append(Finding(
            severity="LOW",
            file=rel,
            issue="Stale backup settings file present",
            fix="Delete it: `rm " + rel + "`",
        ))
        # Still parse it for dangerous settings
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            return findings
    else:
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception:
            return findings

    # Check 1: skipDangerousModePermissionPrompt
    if data.get("skipDangerousModePermissionPrompt") is True:
        findings.append(Finding(
            severity="HIGH",
            file=rel,
            issue="`skipDangerousModePermissionPrompt: true` — disables the dangerous-mode confirmation prompt. "
                  "Any tool invoked in dangerous mode runs without user confirmation.",
            fix="Remove this key from the file",
        ))

    # Check 2: relative hook paths / missing hook scripts
    findings.extend(_check_hook_commands(data, rel))

    # Check 3: floating GitHub marketplace refs
    for name, cfg in data.get("extraKnownMarketplaces", {}).items():
        src = cfg.get("source", {})
        if src.get("source") == "github" and not src.get("ref"):
            findings.append(Finding(
                severity="MEDIUM",
                file=rel,
                issue=f"Marketplace `{name}` loaded from GitHub without a pinned commit ref — "
                      "supply chain risk if the repo is compromised.",
                fix=f'Add `"ref": "<commit-sha>"` inside the source block to pin the version',
            ))

    # Check 4: hardcoded secrets
    for pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(Finding(
                severity="HIGH",
                file=rel,
                issue=f"Possible hardcoded secret matching `{pattern.pattern[:40]}`: "
                      f"`{match.group(0)[:30]}...`",
                fix="Move the secret to an environment variable or a secrets manager",
            ))

    return findings


def find_and_audit() -> list[Finding]:
    """Walk ~/.claude/ and audit every settings JSON file."""
    all_findings: list[Finding] = []

    for root, dirs, files in os.walk(CLAUDE_DIR):
        # Skip large/irrelevant dirs
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "__pycache__", "node_modules", "file-history"}
        ]
        for fname in files:
            if fname in ("settings.json", "settings.json.bak"):
                all_findings.extend(check_settings_file(Path(root) / fname))

    return all_findings


def format_report(findings: list[Finding]) -> str:
    if not findings:
        return "All checks passed. No security issues found in ~/.claude/ configuration."

    by_severity: dict[str, list[Finding]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)

    lines = ["## Claude Code Security Audit Report\n"]
    for sev in ("HIGH", "MEDIUM", "LOW"):
        group = by_severity.get(sev, [])
        if not group:
            continue
        lines.append(f"### {sev} ({len(group)})\n")
        for f in group:
            lines.append(f"**File:** `{f['file']}`")
            lines.append(f"**Issue:** {f['issue']}")
            lines.append(f"**Fix:** {f['fix']}")
            lines.append("")

    total = len(findings)
    lines.append(f"---\n{total} issue{'s' if total != 1 else ''} found.")
    return "\n".join(lines)
