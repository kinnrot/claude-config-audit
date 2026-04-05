#!/usr/bin/env python3
"""
Claude Code Security Audit — SessionStart hook.

Runs automatically on every session start.
Injects a warning systemMessage into the context if HIGH severity issues are found.
Silent if everything looks clean — no output, no noise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow import from same directory
sys.path.insert(0, str(Path(__file__).parent))
from audit_core import find_and_audit


def main() -> None:
    try:
        sys.stdin.read()  # consume stdin (required by hook protocol)
    except Exception:
        sys.exit(0)

    try:
        findings = find_and_audit()
    except Exception:
        sys.exit(0)  # fail open — never block a session

    high = [f for f in findings if f["severity"] == "HIGH"]
    if not high:
        sys.exit(0)

    lines = ["Security audit found HIGH severity issues in your Claude Code config:\n"]
    for f in high:
        lines.append(f"  [{f['severity']}] {f['file']}")
        lines.append(f"  {f['issue']}")
        lines.append(f"  Fix: {f['fix']}")
        lines.append("")
    lines.append("Run /audit for the full report.")

    output = {"systemMessage": "\n".join(lines)}
    print(json.dumps(output))
    sys.exit(0)


if __name__ == "__main__":
    main()
