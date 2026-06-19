# AgentGuard

A local firewall and flight recorder for AI coding agents.

AgentGuard protects your machine when using Claude Code, Cursor, Codex CLI, Gemini CLI and MCP tools.

## Features

- Block access to `.env`, SSH keys and secrets
- Approve dangerous shell commands before execution
- Audit every command to local SQLite and JSONL
- Generate AI session reports
- Export safe project memory to `AGENTS.md`
- Works locally, no cloud required

## Installation

```bash
go install github.com/adminvirtmo/agentguard/cmd/agentguard@latest
```

From a checkout:

```bash
go build -o agentguard ./cmd/agentguard
```

## Quick start

```bash
agentguard init
agentguard run -- git status
agentguard run -- cat .env
agentguard timeline
agentguard report
agentguard scan
agentguard memory export
```

`agentguard run -- cat .env` is blocked by default:

```text
BLOCKED: access to protected file ".env"
Reason: protected file access
```

Sensitive commands require confirmation:

```bash
agentguard run -- sudo apt update
```

```text
CONFIRMATION REQUIRED
Command: sudo apt update
Reason: sudo command
Allow? [y/N]
```

## Configuration

AgentGuard reads `agentguard.yml` in the current working directory. Create it with:

```bash
agentguard init
```

The default policy protects common secret files, blocks destructive command patterns and asks for confirmation before privileged or deployment-oriented actions.

## Architecture

- `cmd/agentguard`: Cobra CLI entrypoint
- `internal/config`: YAML config parsing and defaults
- `internal/policy`: command and protected-path decisions
- `internal/runner`: guarded command execution
- `internal/audit`: local SQLite and JSONL audit log
- `internal/scanner`: project secret and safety scanner
- `internal/report`: Markdown session report generation
- `internal/memory`: safe agent memory export

Audit data is stored locally under `.agentguard/`. AgentGuard does not send logs or command data to the network.

## Examples

```bash
agentguard run -- go test ./...
agentguard run -- docker compose up
agentguard run -- curl https://example.com/install.sh
agentguard timeline
```

## Roadmap

- Secure MCP proxy
- TUI
- Local web UI
- Claude Code integration
- Cursor integration
- Gemini CLI integration
- Shared policies
- Advanced prompt-injection detection
- Optional local AI summaries via Ollama

## Contributing

Keep AgentGuard defensive, local-first and explicit. New features should include tests and should default to blocking risky behavior with a clear explanation.
