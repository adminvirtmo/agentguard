# Security

AgentGuard is a defensive local tool. It blocks or confirms risky agent actions before execution and records an audit trail locally.

## Principles

- Local-only by default
- No hidden network calls
- No cloud dependency
- Block first when risk is clear
- Explain every block or confirmation
- Store audit data in `.agentguard/`

## Reporting Issues

Do not include secrets in issues. Share the policy, command shape and expected behavior, but redact local paths and credentials.
