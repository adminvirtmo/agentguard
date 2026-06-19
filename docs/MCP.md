# MCP

AgentGuard includes an experimental MCP inspection helper:

```bash
echo '{"name":"read_file","params":{"path":".env"}}' | agentguard mcp inspect
```

The command reads a JSON MCP-like tool call, flattens inspectable tool arguments, evaluates them against `agentguard.yml`, and returns a JSON policy decision.

Example blocked decision:

```json
{
  "status": "blocked",
  "reason": "protected file access",
  "tool": "read_file",
  "sensitive_files": [".env"]
}
```

This is not a full MCP proxy yet. The planned proxy mode will sit between an AI agent and MCP servers to enforce local policies before tool calls are executed.

Planned proxy behavior:

- inspect MCP tool calls before execution
- block protected file reads
- confirm sensitive filesystem, shell or network actions
- record MCP activity in the same audit store
- keep all policy and audit data local by default
