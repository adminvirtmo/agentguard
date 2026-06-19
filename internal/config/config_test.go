package config

import (
	"path/filepath"
	"testing"
)

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentguard.yml")
	if err := WriteDefault(path); err != nil {
		t.Fatalf("WriteDefault: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("version = %d, want 1", cfg.Version)
	}
	if len(cfg.Protect.Paths) == 0 || len(cfg.Deny.Commands) == 0 {
		t.Fatal("expected default protect and deny rules")
	}
}

func TestProfiles(t *testing.T) {
	for _, name := range ProfileNames() {
		cfg := Profile(name)
		if cfg.Version != 1 {
			t.Fatalf("profile %s version = %d, want 1", name, cfg.Version)
		}
		if len(cfg.Protect.Paths) == 0 {
			t.Fatalf("profile %s has no protected paths", name)
		}
	}
	if ValidProfile("unknown") {
		t.Fatal("unknown profile should be invalid")
	}
	if len(Profile(ProfileStrict).Deny.Commands) <= len(Profile(ProfilePermissive).Deny.Commands) {
		t.Fatal("strict profile should have more deny rules than permissive")
	}
}
