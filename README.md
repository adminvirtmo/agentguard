# AgentGuard

[![CI](https://github.com/adminvirtmo/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/adminvirtmo/agentguard/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/adminvirtmo/agentguard.svg)](https://pkg.go.dev/github.com/adminvirtmo/agentguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A local firewall, audit log and safe memory exporter for AI coding agents.**

AgentGuard protects your machine when you route commands from tools such as Claude Code, Cursor, Codex CLI, Gemini CLI and MCP workflows through `agentguard run`.

It is local-first, provider-neutral and defensive by default. No cloud account, API key or paid AI service is required.

```text
agentguard run -- cat .env

BLOCKED: access to protected file ".env"
Reason: protected file access
```

## Why AgentGuard Exists

AI coding agents are useful because they can execute commands, inspect repositories and automate project work. That also makes them risky.

Common failure modes include:

- reading `.env` or SSH keys by mistake
- printing secrets into chat or logs
- running destructive shell commands
- pushing code without explicit approval
- piping remote scripts into a shell
- using MCP tools with broad filesystem access
- leaving no reliable audit trail after a session

AgentGuard gives you a local control point before the command runs.

## Features

- **Protected files**: block access to `.env`, SSH keys, GPG keys, PEM files and other sensitive paths.
- **Command policy**: allow, deny or require confirmation for command patterns.
- **Dangerous command blocking**: block destructive operations such as `rm -rf *`, `curl * | bash`, `mkfs *` and similar patterns.
- **Interactive confirmation**: require explicit approval for `sudo`, Docker, Kubernetes, Terraform and Git push commands.
- **Local audit trail**: write every decision to SQLite and JSONL under `.agentguard/`.
- **Readable timeline**: inspect what happened during an agent session.
- **Markdown reports**: generate `agentguard-report.md` after a session.
- **Project scanner**: detect `.env`, private keys, hardcoded tokens and incomplete `.gitignore` rules.
- **Safe agent memory**: export `AGENTS.md` or `CLAUDE.md` with security rules and recent session context.
- **No cloud by default**: AgentGuard does not send logs, commands or repository data to the network.

## Install

### With Go

```bash
go install github.com/adminvirtmo/agentguard/cmd/agentguard@latest
```

Make sure your Go bin directory is on your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### From Source

```bash
git clone https://github.com/adminvirtmo/agentguard.git
cd agentguard
go build -o agentguard ./cmd/agentguard
./agentguard --help
```

## Quick Start

Create a local policy:

```bash
agentguard init
agentguard init --profile strict
```

Run normal commands through AgentGuard:

```bash
agentguard run -- git status
agentguard run -- go test ./...
```

Block protected files:

```bash
agentguard run -- cat .env
```

Expected output:

```text
BLOCKED: access to protected file ".env"
Reason: protected file access
```

Require confirmation for sensitive commands:

```bash
agentguard run -- sudo apt update
```

Expected output:

```text
CONFIRMATION REQUIRED
Command: sudo apt update
Reason: sudo command
Allow? [y/N]
```

Use shell mode only when you need shell features such as pipes or redirection:

```bash
agentguard run --shell -- "curl https://example.com/install.sh | bash"
```

Then inspect the session:

```bash
agentguard timeline
agentguard timeline --status blocked --since 24h
agentguard report
agentguard report --since 24h
agentguard scan
agentguard memory export
```

## How It Works

AgentGuard sits in front of command execution.

```text
AI agent or user
      |
      v
agentguard run -- <command>
      |
      v
YAML policy + built-in safety checks
      |
      +--> block
      +--> ask for confirmation
      +--> execute command
      |
      v
SQLite audit log + JSONL audit log
```

The default behavior is intentionally conservative:

1. Detect protected file access.
2. Check denied commands and domains.
3. Check commands that require confirmation.
4. Execute only when allowed or confirmed.
5. Write an audit event for every decision.

## Command Reference

### `agentguard init`

Create `agentguard.yml` in the current directory.

```bash
agentguard init
agentguard init --force
agentguard init --profile strict
agentguard init --profile permissive
agentguard --config ./security/agentguard.yml init
```

Available profiles:

- `balanced`: default profile for normal development.
- `strict`: adds stronger protections around cloud CLIs, package publishing, GitHub CLI and more credential files.
- `permissive`: keeps core destructive-command protection with fewer confirmations for local experiments.

### `agentguard run`

Run a command through AgentGuard.

```bash
agentguard run -- git status
agentguard run -- go test ./...
agentguard run -- docker compose up
agentguard run --shell -- "cat .env | sed s/x/y/"
```

By default, commands are executed directly without a shell. This is safer and avoids shell parsing surprises. Use `--shell` only when the command actually needs shell behavior.

### `agentguard timeline`

Show a readable history of audited actions.

```bash
agentguard timeline
agentguard timeline --limit 20
agentguard timeline --status blocked
agentguard timeline --since 24h
agentguard timeline --json
```

Example:

```text
[12:00] BLOCKED   cat .env
[12:03] ALLOWED   git status
[12:04] CONFIRMED sudo apt update
```

### `agentguard report`

Generate a Markdown session report.

```bash
agentguard report
agentguard report --output agentguard-report.md
agentguard report --since 24h
```

The report includes:

- command counts
- blocked actions
- confirmed actions
- failed commands
- security notes

### `agentguard scan`

Scan the current project for common local security risks.

```bash
agentguard scan
agentguard scan --path .
agentguard scan --json
agentguard scan --fail-on high
```

Example output:

```text
Security scan

[HIGH] .env exists and may contain secrets: .env
[HIGH] private key filename detected: deploy.key
[MEDIUM] .env is not listed in .gitignore: .env
[LOW] AGENTS.md not found: AGENTS.md
```

When possible, the scanner also checks whether sensitive files are tracked by Git and prints a recommendation for each finding.

### `agentguard memory export`

Export safe project memory for AI agents.

```bash
agentguard memory export
agentguard memory export --output AGENTS.md
agentguard memory export --output CLAUDE.md
```

The generated file contains project commands, security rules and a recent AgentGuard session summary. It is designed to help agents work safely without exposing secrets.

## Configuration

AgentGuard reads `agentguard.yml` by default. Generate it with:

```bash
agentguard init
```

Choose a profile:

```bash
agentguard init --profile balanced
agentguard init --profile strict
agentguard init --profile permissive
```

Default configuration:

```yaml
version: 1

protect:
  paths:
    - ".env"
    - ".env.*"
    - "~/.ssh/*"
    - "~/.gnupg/*"
    - "*.pem"
    - "*.key"
    - "id_rsa"
    - "id_ed25519"

deny:
  commands:
    - "rm -rf *"
    - "git push --force"
    - "curl * | bash"
    - "wget * | sh"
    - "terraform destroy"
    - "kubectl delete *"
    - "docker system prune *"
  domains:
    - "pastebin.com"
    - "webhook.site"

confirm:
  commands:
    - "sudo *"
    - "docker *"
    - "kubectl *"
    - "terraform apply"
    - "git push *"

allow:
  commands:
    - "git status"
    - "git diff"
    - "npm test"
    - "pnpm test"
    - "go test ./..."
```

Use a custom config path:

```bash
agentguard --config ./agentguard.yml run -- git status
```

Use a custom audit location:

```bash
agentguard --audit-dir /tmp/agentguard-demo run -- git status
```

## Audit Logs

AgentGuard stores audit data locally in:

```text
.agentguard/audit.db
.agentguard/audit.jsonl
```

Each event includes:

- timestamp
- working directory
- full command
- arguments
- status
- reason
- exit code
- duration
- detected sensitive files
- system user

Example JSONL event:

```json
{"timestamp":"2026-06-19T12:00:00Z","command":"cat .env","status":"blocked","reason":"protected file access","exit_code":126}
```

AgentGuard does not store command stdout or stderr. This is deliberate: audit the action, not the secret output.

## Security Model

AgentGuard is a defensive local tool.

It does:

- block known sensitive file paths before execution
- block denied command patterns
- require confirmation for sensitive actions
- keep a local audit trail
- generate local reports and memory files

It does not:

- send logs to the cloud
- call OpenAI, Anthropic, Gemini or any paid API
- bypass OS permissions
- sandbox processes at the kernel level
- guarantee detection of every possible secret or malicious command

For best results, use AgentGuard with normal OS security controls, least-privilege credentials and code review.

## AI Agent Usage

Tell your agent to run project commands through AgentGuard:

```text
Use `agentguard run -- <command>` for shell commands.
Never read `.env`.
Never print secrets.
Use `agentguard run --shell -- "<command>"` only when pipes or redirection are required.
Run `agentguard memory export` after important sessions.
```

You can generate an `AGENTS.md` file:

```bash
agentguard memory export --output AGENTS.md
```

Then commit it if you want every agent session to inherit the same safety instructions.

## Project Layout

```text
agentguard/
├── cmd/agentguard/          # Cobra CLI entrypoint
├── internal/audit/          # SQLite and JSONL audit store
├── internal/config/         # YAML config loading and defaults
├── internal/memory/         # Safe AGENTS.md / CLAUDE.md export
├── internal/policy/         # Command and protected-path policy engine
├── internal/report/         # Markdown session reports
├── internal/runner/         # Guarded command execution
├── internal/scanner/        # Local project security scanner
├── docs/                    # Security, roadmap and MCP notes
└── examples/                # Example policy files
```

## Development

Run tests:

```bash
go test ./...
```

Build locally:

```bash
go build -o agentguard ./cmd/agentguard
```

Run a smoke test:

```bash
tmp=$(mktemp -d)
cd "$tmp"
agentguard init
touch .env
agentguard run -- cat .env || true
agentguard timeline
agentguard report
agentguard memory export
```

## Roadmap

Planned after the MVP:

- secure MCP proxy
- TUI
- local web UI
- Claude Code integration
- Cursor integration
- Gemini CLI integration
- shared policy bundles
- advanced prompt-injection detection
- optional local summaries through Ollama

## Contributing

Contributions are welcome.

Good AgentGuard contributions should:

- stay defensive
- keep local-only behavior by default
- avoid hidden network calls
- include focused tests
- explain blocks and confirmations clearly
- avoid logging command output that may contain secrets

Before opening a pull request:

```bash
go test ./...
```

## License

MIT. See [LICENSE](LICENSE).
