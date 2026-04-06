# claude-config-audit

A Claude Code plugin that audits your `~/.claude/` configuration for security misconfigurations and potential data leaks.

## What it does

**On every session start** — silently scans your config. If HIGH severity issues are found, injects a warning into Claude's context so it can tell you immediately.

**`/audit` skill** — run manually at any time for the full report.

## Checks

| Severity | Check |
|---|---|
| HIGH | `skipDangerousModePermissionPrompt: true` present in any settings file |
| HIGH | Hardcoded secrets/tokens (OpenAI, GitHub PAT, Slack, JWT, Vercel) |
| MEDIUM | Hook commands using relative paths (CWD-dependent, hijackable) |
| MEDIUM | Hook scripts that don't exist on disk |
| MEDIUM | Marketplace sources loaded from GitHub without a pinned commit `ref` |
| LOW | Stale `.bak` settings files |

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/kinnrot/claude-config-audit ~/.claude/plugins/cache/claude-config-audit
```

### 2. Register in `~/.claude/settings.json`

```json
{
  "extraKnownMarketplaces": {
    "claude-config-audit": {
      "source": {
        "source": "directory",
        "path": "/Users/<your-username>/.claude/plugins/cache/claude-config-audit"
      }
    }
  }
}
```

### 3. Install and reload

Inside Claude Code:

```
/plugin install claude-config-audit@claude-config-audit
/reload-plugins
```

### Updating

```bash
cd ~/.claude/plugins/cache/claude-config-audit && git pull
```

Then `/reload-plugins` in Claude Code.

## Usage

The SessionStart hook runs automatically — no action needed after install.

For a manual full audit at any time, type `/audit` in any Claude Code session.

## Design principles

- **Fail open** — any error in the hook exits cleanly. It never blocks a session.
- **Silent when clean** — no output unless there's something to report.
- **No external dependencies** — pure Python stdlib only.
