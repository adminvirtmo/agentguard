package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adminvirtmo/agentguard/internal/audit"
)

func TestGenerateReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	events := []audit.Event{
		{Command: "cat .env", Status: "blocked", Reason: "protected file access"},
		{Command: "go test ./...", Status: "allowed", Reason: "allowed by default"},
	}
	if err := Generate(events, path); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "Blocked actions: 1") || !strings.Contains(text, "`cat .env`") {
		t.Fatalf("unexpected report:\n%s", text)
	}
}

func TestGenerateJSONReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	events := []audit.Event{
		{Command: "cat .env", Status: "blocked", Reason: "protected file access"},
		{Command: "go test ./...", Status: "allowed", Reason: "allowed by default"},
	}
	if err := GenerateJSON(events, path); err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var doc Document
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if doc.Summary.BlockedActions != 1 || len(doc.BlockedActions) != 1 {
		t.Fatalf("unexpected JSON report: %#v", doc)
	}
}
