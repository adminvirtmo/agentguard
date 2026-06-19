package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adminvirtmo/agentguard/internal/audit"
	"github.com/adminvirtmo/agentguard/internal/config"
)

type Status string

const (
	OK      Status = "ok"
	Warning Status = "warning"
	Error   Status = "error"
)

type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

func Run(configPath, auditDir string) []Check {
	return []Check{
		checkExecutable(),
		checkGo(),
		checkGit(),
		checkConfig(configPath),
		checkAudit(auditDir),
		checkGitignore(),
	}
}

func Healthy(checks []Check) bool {
	for _, check := range checks {
		if check.Status == Error {
			return false
		}
	}
	return true
}

func checkExecutable() Check {
	path, err := os.Executable()
	if err != nil {
		return Check{Name: "agentguard binary", Status: Warning, Message: "could not resolve current executable"}
	}
	return Check{Name: "agentguard binary", Status: OK, Message: path}
}

func checkGo() Check {
	if path, err := exec.LookPath("go"); err == nil {
		return Check{Name: "go", Status: OK, Message: path}
	}
	return Check{Name: "go", Status: Warning, Message: "go was not found on PATH", Fix: "Install Go if you want to build or install AgentGuard from source."}
}

func checkGit() Check {
	if path, err := exec.LookPath("git"); err == nil {
		return Check{Name: "git", Status: OK, Message: path}
	}
	return Check{Name: "git", Status: Warning, Message: "git was not found on PATH", Fix: "Install Git for repository tracking checks in agentguard scan."}
}

func checkConfig(path string) Check {
	cfg, err := config.Load(path)
	if err != nil {
		return Check{Name: "config", Status: Error, Message: fmt.Sprintf("cannot load %s: %v", path, err), Fix: "Run agentguard init --profile strict."}
	}
	if cfg.Version != 1 {
		return Check{Name: "config", Status: Warning, Message: fmt.Sprintf("unsupported config version %d", cfg.Version)}
	}
	return Check{Name: "config", Status: OK, Message: fmt.Sprintf("%s loaded", path)}
}

func checkAudit(dir string) Check {
	store, err := audit.Open(dir)
	if err != nil {
		return Check{Name: "audit", Status: Error, Message: fmt.Sprintf("cannot open audit store: %v", err), Fix: "Check filesystem permissions for the audit directory."}
	}
	defer store.Close()
	return Check{Name: "audit", Status: OK, Message: filepath.Join(dir, audit.Dir)}
}

func checkGitignore() Check {
	b, err := os.ReadFile(".gitignore")
	if err != nil {
		return Check{Name: ".gitignore", Status: Warning, Message: ".gitignore not found", Fix: "Add .agentguard/ and local report outputs to .gitignore."}
	}
	content := string(b)
	if !containsAll(content, []string{".agentguard/", "agentguard-report.md"}) {
		return Check{Name: ".gitignore", Status: Warning, Message: ".gitignore is missing AgentGuard local outputs", Fix: "Add .agentguard/ and agentguard-report.md."}
	}
	return Check{Name: ".gitignore", Status: OK, Message: "AgentGuard local outputs are ignored"}
}

func containsAll(s string, needles []string) bool {
	for _, needle := range needles {
		if !strings.Contains(s, needle) {
			return false
		}
	}
	return true
}
