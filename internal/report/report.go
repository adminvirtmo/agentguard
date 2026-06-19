package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adminvirtmo/agentguard/internal/audit"
)

const DefaultPath = "agentguard-report.md"

type Summary struct {
	CommandsExecuted int `json:"commands_executed"`
	BlockedActions   int `json:"blocked_actions"`
	ConfirmedActions int `json:"confirmed_actions"`
	FailedCommands   int `json:"failed_commands"`
}

type Document struct {
	Summary          Summary       `json:"summary"`
	BlockedActions   []audit.Event `json:"blocked_actions"`
	CommandsExecuted []audit.Event `json:"commands_executed"`
	SecurityNotes    []string      `json:"security_notes"`
}

func Generate(events []audit.Event, path string) error {
	doc := Build(events)
	var b strings.Builder
	fmt.Fprintln(&b, "# AgentGuard Session Report")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Summary")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Commands executed: %d\n", doc.Summary.CommandsExecuted)
	fmt.Fprintf(&b, "- Blocked actions: %d\n", doc.Summary.BlockedActions)
	fmt.Fprintf(&b, "- Confirmed actions: %d\n", doc.Summary.ConfirmedActions)
	fmt.Fprintf(&b, "- Failed commands: %d\n", doc.Summary.FailedCommands)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Blocked actions")
	fmt.Fprintln(&b)
	writeEvents(&b, doc.BlockedActions, true)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Commands executed")
	fmt.Fprintln(&b)
	writeEvents(&b, doc.CommandsExecuted, false)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Security notes")
	fmt.Fprintln(&b)
	for _, note := range doc.SecurityNotes {
		fmt.Fprintf(&b, "- %s\n", note)
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func GenerateJSON(events []audit.Event, path string) error {
	b, err := json.MarshalIndent(Build(events), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func Build(events []audit.Event) Document {
	doc := Document{
		Summary: Summary{
			CommandsExecuted: len(events),
			BlockedActions:   countStatus(events, "blocked"),
			ConfirmedActions: countStatus(events, "confirmed"),
			FailedCommands:   countStatus(events, "failed"),
		},
	}
	for _, e := range events {
		switch e.Status {
		case "blocked":
			doc.BlockedActions = append(doc.BlockedActions, e)
		case "allowed", "confirmed", "failed":
			doc.CommandsExecuted = append(doc.CommandsExecuted, e)
		}
	}
	if doc.Summary.BlockedActions > 0 {
		doc.SecurityNotes = append(doc.SecurityNotes, "Protected or dangerous actions were blocked.")
	} else {
		doc.SecurityNotes = append(doc.SecurityNotes, "No blocked actions were recorded.")
	}
	doc.SecurityNotes = append(doc.SecurityNotes, "No command output is stored by AgentGuard.")
	return doc
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

func writeEvents(b *strings.Builder, events []audit.Event, includeReason bool) {
	wrote := false
	for _, e := range events {
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
