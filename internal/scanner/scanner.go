package scanner

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Severity string

const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
	Low    Severity = "LOW"
)

type Finding struct {
	Severity       Severity `json:"severity"`
	Type           string   `json:"type,omitempty"`
	Path           string   `json:"path,omitempty"`
	Line           int      `json:"line,omitempty"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation,omitempty"`
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

type secretPattern struct {
	kind string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{kind: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{kind: "generic-secret", re: regexp.MustCompile(`(?i)(api[_-]?key|token|secret)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}`)},
	{kind: "github-token", re: regexp.MustCompile(`ghp_[A-Za-z0-9]{30,}`)},
	{kind: "openai-token", re: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{kind: "aws-access-key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{kind: "slack-token", re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{20,}`)},
	{kind: "bearer-token", re: regexp.MustCompile(`(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{20,}`)},
}

func Scan(root string) ([]Finding, error) {
	var findings []Finding
	gitignore := loadGitignore(filepath.Join(root, ".gitignore"))
	tracked := gitTrackedFiles(root)
	if exists(filepath.Join(root, ".env")) {
		findings = append(findings, Finding{Severity: High, Type: "sensitive-file", Path: ".env", Message: ".env exists and may contain secrets", Recommendation: "Keep .env local, add it to .gitignore, and store only .env.example in Git."})
		if !ignored(gitignore, ".env") {
			findings = append(findings, Finding{Severity: Medium, Type: "gitignore", Path: ".env", Message: ".env is not listed in .gitignore", Recommendation: "Add .env and .env.* to .gitignore."})
		}
		if tracked[".env"] {
			findings = append(findings, Finding{Severity: High, Type: "git-tracked-secret", Path: ".env", Message: ".env is tracked by Git", Recommendation: "Remove it from Git history or at least run git rm --cached .env and rotate exposed secrets."})
		}
	}
	if !exists(filepath.Join(root, "AGENTS.md")) {
		findings = append(findings, Finding{Severity: Low, Type: "agent-memory", Path: "AGENTS.md", Message: "AGENTS.md not found", Recommendation: "Run agentguard memory export to create safe instructions for AI agents."})
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
			findings = append(findings, Finding{Severity: High, Type: "private-key-file", Path: rel, Message: "private key filename detected", Recommendation: "Move private keys out of the repository and rotate them if they were committed."})
			if tracked[filepath.ToSlash(rel)] {
				findings = append(findings, Finding{Severity: High, Type: "git-tracked-secret", Path: rel, Message: "private key is tracked by Git", Recommendation: "Remove it from Git history and rotate the key."})
			}
		}
		if shouldInspect(name) {
			match, _ := fileSecretMatch(path)
			if match.found {
				findings = append(findings, Finding{Severity: High, Type: match.kind, Path: rel, Line: match.line, Message: "potential secret detected in file", Recommendation: "Move the value to a local secret store or environment variable and rotate it if it was committed."})
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
		location := f.Path
		if f.Line > 0 {
			location += ":" + strconv.Itoa(f.Line)
		}
		if f.Path != "" {
			b.WriteString("[" + string(f.Severity) + "] " + f.Message + ": " + location + "\n")
		} else {
			b.WriteString("[" + string(f.Severity) + "] " + f.Message + "\n")
		}
		if f.Recommendation != "" {
			b.WriteString("       -> " + f.Recommendation + "\n")
		}
	}
	return b.String()
}

func gitTrackedFiles(root string) map[string]bool {
	tracked := map[string]bool{}
	cmd := exec.Command("git", "-C", root, "ls-files")
	out, err := cmd.Output()
	if err != nil {
		return tracked
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			tracked[filepath.ToSlash(line)] = true
		}
	}
	return tracked
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

type secretMatch struct {
	found bool
	kind  string
	line  int
}

func fileSecretMatch(path string) (secretMatch, error) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 2*1024*1024 {
		return secretMatch{}, err
	}
	if looksBinary(b) {
		return secretMatch{}, nil
	}
	for _, pattern := range secretPatterns {
		if loc := pattern.re.FindIndex(b); loc != nil {
			return secretMatch{found: true, kind: pattern.kind, line: lineForOffset(b, loc[0])}, nil
		}
	}
	return secretMatch{}, nil
}

func fileContainsSecret(path string) (bool, error) {
	match, err := fileSecretMatch(path)
	return match.found, err
}

func lineForOffset(b []byte, offset int) int {
	line := 1
	for i := 0; i < offset && i < len(b); i++ {
		if b[i] == '\n' {
			line++
		}
	}
	return line
}

func looksBinary(b []byte) bool {
	limit := len(b)
	if limit > 8000 {
		limit = 8000
	}
	for i := 0; i < limit; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}
