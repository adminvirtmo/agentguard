# MCP

AgentGuard does not implement an MCP proxy yet. The planned MCP mode will sit between an AI agent and MCP servers to enforce local policies before tool calls are executed.

Planned behavior:

- Inspect MCP tool calls before execution
- Block protected file reads
- Confirm sensitive filesystem, shell or network actions
- Record MCP activity in the same audit store
- Keep all policy and audit data local by default
