package runner

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/adminvirtmo/agentguard/internal/audit"
	"github.com/adminvirtmo/agentguard/internal/config"
)

func TestRunnerBlocksProtectedFile(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	var out bytes.Buffer
	r := Runner{Config: config.Default(), Audit: store, Out: &out, Err: &bytes.Buffer{}}
	code := r.Run(context.Background(), []string{"cat", ".env"})
	if code != 126 {
		t.Fatalf("exit code = %d, want 126", code)
	}
	if !strings.Contains(out.String(), "BLOCKED") {
		t.Fatalf("expected blocked output, got %q", out.String())
	}
	events, err := store.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 || events[0].Status != "blocked" {
		t.Fatalf("unexpected audit events: %#v", events)
	}
}

func TestRunnerShellDetectsProtectedFileInCommandString(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	var out bytes.Buffer
	r := Runner{Config: config.Default(), Audit: store, Out: &out, Err: &bytes.Buffer{}, Shell: true}
	code := r.Run(context.Background(), []string{"cat .env"})
	if code != 126 {
		t.Fatalf("exit code = %d, want 126", code)
	}
	if !strings.Contains(out.String(), `".env"`) {
		t.Fatalf("expected protected file in output, got %q", out.String())
	}
}

func TestRunnerAllowsCommand(t *testing.T) {
	dir := t.TempDir()
	store, err := audit.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	var out bytes.Buffer
	r := Runner{Config: config.Default(), Audit: store, Out: &out, Err: &bytes.Buffer{}}
	code := r.Run(context.Background(), []string{"go", "version"})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "go version") {
		t.Fatalf("expected go version output, got %q", out.String())
	}
}
