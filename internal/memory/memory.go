package memory

import (
	"fmt"
	"os"
	"strings"

	"github.com/adminvirtmo/agentguard/internal/audit"
)

const DefaultPath = "AGENTS.md"

func Export(events []audit.Event, path string) error {
	var b strings.Builder
	fmt.Fprintln(&b, "# Agent Memory")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Project commands")
	fmt.Fprintln(&b)
	for _, cmd := range projectCommands(events) {
		fmt.Fprintf(&b, "- `%s`\n", cmd)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Security rules")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "- Never read `.env`.")
	fmt.Fprintln(&b, "- Never print secrets.")
	fmt.Fprintln(&b, "- Never run destructive commands without confirmation.")
	fmt.Fprintln(&b, "- Never push to Git without explicit user confirmation.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Recent session summary")
	fmt.Fprintln(&b)
	for _, line := range sessionSummary(events) {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func projectCommands(events []audit.Event) []string {
	defaults := []string{"go test ./..."}
	seen := map[string]bool{}
	var cmds []string
	for _, e := range events {
		if e.Status != "allowed" && e.Status != "confirmed" {
			continue
		}
		if strings.Contains(e.Command, "test") || strings.Contains(e.Command, "lint") || strings.HasPrefix(e.Command, "go ") {
			if !seen[e.Command] {
				cmds = append(cmds, e.Command)
				seen[e.Command] = true
			}
		}
	}
	if len(cmds) == 0 {
		return defaults
	}
	return cmds
}

func sessionSummary(events []audit.Event) []string {
	if len(events) == 0 {
		return []string{"No AgentGuard session events have been recorded yet."}
	}
	var lines []string
	for _, e := range events {
		switch e.Status {
		case "blocked":
			lines = append(lines, fmt.Sprintf("`%s` was blocked: %s.", e.Command, e.Reason))
		case "confirmed":
			lines = append(lines, fmt.Sprintf("`%s` was confirmed and executed.", e.Command))
		case "allowed":
			lines = append(lines, fmt.Sprintf("`%s` was allowed.", e.Command))
		}
	}
	if len(lines) == 0 {
		return []string{"Recent events did not include allowed or blocked commands."}
	}
	if len(lines) > 10 {
		return lines[len(lines)-10:]
	}
	return lines
}
