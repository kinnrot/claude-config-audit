---
name: audit
description: Security audit of Claude Code configuration — scans ~/.claude/ settings files for misconfigurations, unsafe settings, relative hook paths, floating plugin refs, and hardcoded secrets.
user-invocable: true
---

# /audit — Claude Code Security Audit

Perform a full security audit of the Claude Code configuration under `~/.claude/`.

## How to run

Execute the audit script directly and display the formatted report:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/hooks/session_audit_hook.py
```

Wait — the session hook only outputs a systemMessage JSON for HIGH findings.
For the full report, run the core auditor inline:

```python
import sys
sys.path.insert(0, "${CLAUDE_PLUGIN_ROOT}/hooks")
from audit_core import find_and_audit, format_report
findings = find_and_audit()
print(format_report(findings))
```

## What gets checked

| Severity | Check |
|---|---|
| HIGH | `skipDangerousModePermissionPrompt: true` in any settings.json |
| HIGH | Hardcoded secrets/tokens (OpenAI, GitHub PAT, Slack, JWT, Vercel) |
| MEDIUM | Hook commands using relative paths instead of absolute or `${CLAUDE_PLUGIN_ROOT}` |
| MEDIUM | Hook scripts referenced that don't exist on disk |
| MEDIUM | Marketplace sources loaded from GitHub without a pinned `ref` commit hash |
| LOW | Stale `.bak` settings files present |

## Output format

```
## Claude Code Security Audit Report

### HIGH (n)
**File:** `~/.claude/settings.json`
**Issue:** ...
**Fix:** ...

### MEDIUM (n)
...

### LOW (n)
...

---
N issues found.
```

If no issues found: "All checks passed."

## Instructions

Run the audit by using the Bash tool to execute:

```bash
cd /tmp && python3 -c "
import sys
sys.path.insert(0, '${CLAUDE_PLUGIN_ROOT}/hooks')
from audit_core import find_and_audit, format_report
print(format_report(find_and_audit()))
"
```

Then display the output to the user as-is.
