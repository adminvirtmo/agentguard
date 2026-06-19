package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/adminvirtmo/agentguard/internal/audit"
)

const DefaultPath = "agentguard-report.md"

func Generate(events []audit.Event, path string) error {
	var b strings.Builder
	total := len(events)
	blocked := countStatus(events, "blocked")
	confirmed := countStatus(events, "confirmed")
	failed := countStatus(events, "failed")
	fmt.Fprintln(&b, "# AgentGuard Session Report")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Summary")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Commands executed: %d\n", total)
	fmt.Fprintf(&b, "- Blocked actions: %d\n", blocked)
	fmt.Fprintf(&b, "- Confirmed actions: %d\n", confirmed)
	fmt.Fprintf(&b, "- Failed commands: %d\n", failed)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Blocked actions")
	fmt.Fprintln(&b)
	writeFiltered(&b, events, "blocked", true)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Commands executed")
	fmt.Fprintln(&b)
	for _, e := range events {
		if e.Status == "allowed" || e.Status == "confirmed" || e.Status == "failed" {
			fmt.Fprintf(&b, "- `%s`\n", e.Command)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Security notes")
	fmt.Fprintln(&b)
	if blocked > 0 {
		fmt.Fprintln(&b, "- Protected or dangerous actions were blocked.")
	} else {
		fmt.Fprintln(&b, "- No blocked actions were recorded.")
	}
	fmt.Fprintln(&b, "- No command output is stored by AgentGuard.")
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func countStatus(events []audit.Event, status string) int {
	n := 0
	for _, e := range events {
		if e.Status == status {
			n++
		}
	}
	return n
}

func writeFiltered(b *strings.Builder, events []audit.Event, status string, includeReason bool) {
	wrote := false
	for _, e := range events {
		if e.Status != status {
			continue
		}
		wrote = true
		if includeReason {
			fmt.Fprintf(b, "- `%s` - %s\n", e.Command, e.Reason)
		} else {
			fmt.Fprintf(b, "- `%s`\n", e.Command)
		}
	}
	if !wrote {
		fmt.Fprintln(b, "- None")
	}
}
