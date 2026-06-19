package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestScanFindsEnvAndSecret(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.key"), []byte("-----BEGIN PRIVATE KEY-----\nsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("expected multiple findings, got %#v", findings)
	}
	if !HasSeverityAtLeast(findings, Medium) {
		t.Fatalf("expected findings at or above medium, got %#v", findings)
	}
	if HasSeverityAtLeast(findings, ParseSeverity("invalid")) {
		t.Fatal("invalid severity should not match")
	}
	foundLine := false
	for _, finding := range findings {
		if finding.Path == ".env" && finding.Type == "generic-secret" && finding.Line == 1 {
			foundLine = true
		}
	}
	if !foundLine {
		t.Fatalf("expected secret line finding, got %#v", findings)
	}
}

func TestScanFindsTrackedEnv(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY=abcdefghijklmnopqrstuvwxyz123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".env")
	runGit(t, dir, "commit", "-m", "track env")

	findings, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !slices.ContainsFunc(findings, func(f Finding) bool {
		return f.Path == ".env" && f.Message == ".env is tracked by Git"
	}) {
		t.Fatalf("expected tracked env finding, got %#v", findings)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}
