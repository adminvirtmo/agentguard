package mcp

import (
	"testing"

	"github.com/adminvirtmo/agentguard/internal/config"
)

func TestInspectBlocksProtectedFile(t *testing.T) {
	payload := []byte(`{"name":"read_file","params":{"path":".env"}}`)
	decision, err := Inspect(config.Default(), payload)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if decision.Status != "blocked" || len(decision.SensitiveFiles) != 1 {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestInspectAllowsUnrelatedCall(t *testing.T) {
	payload := []byte(`{"name":"list_directory","params":{"path":"."}}`)
	decision, err := Inspect(config.Default(), payload)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if decision.Status == "blocked" {
		t.Fatalf("unexpected blocked decision: %#v", decision)
	}
}
