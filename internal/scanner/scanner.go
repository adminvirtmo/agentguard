package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Severity string

const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
	Low    Severity = "LOW"
)

type Finding struct {
	Severity Severity
	Path     string
	Message  string
}

func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	default:
		return ""
	}
}

func HasSeverityAtLeast(findings []Finding, min Severity) bool {
	if min == "" {
		return false
	}
	for _, f := range findings {
		if severityRank(f.Severity) >= severityRank(min) {
			return true
		}
	}
	return false
}

func severityRank(s Severity) int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(api[_-]?key|token|secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{30,}`),
	regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
}

func Scan(root string) ([]Finding, error) {
	var findings []Finding
	gitignore := loadGitignore(filepath.Join(root, ".gitignore"))
	if exists(filepath.Join(root, ".env")) {
		findings = append(findings, Finding{Severity: High, Path: ".env", Message: ".env exists and may contain secrets"})
		if !ignored(gitignore, ".env") {
			findings = append(findings, Finding{Severity: Medium, Path: ".env", Message: ".env is not listed in .gitignore"})
		}
	}
	if !exists(filepath.Join(root, "AGENTS.md")) {
		findings = append(findings, Finding{Severity: Low, Path: "AGENTS.md", Message: "AGENTS.md not found"})
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == ".agentguard" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if isPrivateKeyName(name) {
			findings = append(findings, Finding{Severity: High, Path: rel, Message: "private key filename detected"})
		}
		if shouldInspect(name) {
			found, _ := fileContainsSecret(path)
			if found {
				findings = append(findings, Finding{Severity: High, Path: rel, Message: "potential secret detected in file"})
			}
		}
		return nil
	})
	return findings, err
}

func Format(findings []Finding) string {
	var b strings.Builder
	b.WriteString("Security scan\n\n")
	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	for _, f := range findings {
		if f.Path != "" {
			b.WriteString("[" + string(f.Severity) + "] " + f.Message + ": " + f.Path + "\n")
		} else {
			b.WriteString("[" + string(f.Severity) + "] " + f.Message + "\n")
		}
	}
	return b.String()
}

func loadGitignore(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, strings.TrimPrefix(line, "/"))
		}
	}
	return patterns
}

func ignored(patterns []string, target string) bool {
	for _, p := range patterns {
		if p == target || p == target+"/" {
			return true
		}
		if ok, _ := filepath.Match(p, target); ok {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isPrivateKeyName(name string) bool {
	return strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || name == "id_rsa" || name == "id_ed25519"
}

func shouldInspect(name string) bool {
	ext := filepath.Ext(name)
	switch ext {
	case ".go", ".js", ".ts", ".tsx", ".jsx", ".py", ".rb", ".java", ".env", ".yml", ".yaml", ".json", ".md", ".txt", ".sh":
		return true
	default:
		return name == ".env"
	}
}

func fileContainsSecret(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 2*1024*1024 {
		return false, err
	}
	for _, re := range secretPatterns {
		if re.Match(b) {
			return true, nil
		}
	}
	return false, nil
}
