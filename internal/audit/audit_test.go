package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreAddListAndJSONL(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.Add(Event{
		Timestamp:      "2026-06-19T12:00:00Z",
		WorkingDir:     dir,
		Command:        "cat .env",
		Args:           []string{"cat", ".env"},
		Status:         "blocked",
		Reason:         "protected file access",
		ExitCode:       126,
		DurationMillis: time.Millisecond.Milliseconds(),
		SensitiveFiles: []string{".env"},
		User:           "tester",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	events, err := store.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 || events[0].Command != "cat .env" || events[0].SensitiveFiles[0] != ".env" {
		t.Fatalf("unexpected events: %#v", events)
	}

	b, err := os.ReadFile(filepath.Join(dir, Dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(b), `"command":"cat .env"`) {
		t.Fatalf("jsonl missing event: %s", string(b))
	}
}

func TestStoreListLimitReturnsMostRecentInAscendingOrder(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	for _, command := range []string{"one", "two", "three"} {
		if err := store.Add(Event{WorkingDir: dir, Command: command, Args: []string{command}, Status: "allowed", Reason: "test"}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	events, err := store.List(2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 || events[0].Command != "two" || events[1].Command != "three" {
		t.Fatalf("unexpected limited events: %#v", events)
	}
}
