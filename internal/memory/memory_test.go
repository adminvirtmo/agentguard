package memory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adminvirtmo/agentguard/internal/audit"
)

func TestExportMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AGENTS.md")
	events := []audit.Event{
		{Command: "go test ./...", Status: "allowed"},
		{Command: "cat .env", Status: "blocked", Reason: "protected file access"},
	}
	if err := Export(events, path); err != nil {
		t.Fatalf("Export: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "Never read `.env`.") || !strings.Contains(text, "`go test ./...`") {
		t.Fatalf("unexpected memory export:\n%s", text)
	}
}
