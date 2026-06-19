package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/adminvirtmo/agentguard/internal/config"
)

type Status string

const (
	StatusAllowed   Status = "allowed"
	StatusBlocked   Status = "blocked"
	StatusConfirm   Status = "confirm"
	StatusDenied    Status = "denied"
	StatusFailed    Status = "failed"
	StatusConfirmed Status = "confirmed"
)

type Decision struct {
	Status         Status
	Reason         string
	SensitiveFiles []string
	MatchedRule    string
}

func Evaluate(cfg config.Config, args []string) Decision {
	cmd := strings.Join(args, " ")
	if cmd == "" {
		return Decision{Status: StatusBlocked, Reason: "empty command"}
	}
	for _, p := range DetectProtectedPaths(cfg.Protect.Paths, args) {
		return Decision{Status: StatusBlocked, Reason: "protected file access", SensitiveFiles: []string{p}}
	}
	for _, domain := range cfg.Deny.Domains {
		if strings.Contains(cmd, domain) {
			return Decision{Status: StatusBlocked, Reason: "blocked domain", MatchedRule: domain}
		}
	}
	denyRules := append(defaultDenyCommands(), cfg.Deny.Commands...)
	if rule := firstMatch(denyRules, cmd); rule != "" {
		return Decision{Status: StatusBlocked, Reason: reasonForDeny(rule), MatchedRule: rule}
	}
	if rule := firstMatch(cfg.Confirm.Commands, cmd); rule != "" {
		return Decision{Status: StatusConfirm, Reason: reasonForConfirm(rule), MatchedRule: rule}
	}
	return Decision{Status: StatusAllowed, Reason: "allowed by default"}
}

func DetectProtectedPaths(patterns, args []string) []string {
	var found []string
	seen := map[string]bool{}
	for _, arg := range args {
		for _, token := range pathTokens(arg) {
			for _, pattern := range patterns {
				if protectedPathMatch(pattern, token) && !seen[token] {
					found = append(found, token)
					seen[token] = true
				}
			}
		}
	}
	return found
}

func pathTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("|;&<>(){}", r)
	})
}

func firstMatch(patterns []string, command string) string {
	for _, pattern := range patterns {
		if CommandMatches(pattern, command) {
			return pattern
		}
	}
	return ""
}

func CommandMatches(pattern, command string) bool {
	p := strings.Join(strings.Fields(pattern), " ")
	c := strings.Join(strings.Fields(command), " ")
	if p == c {
		return true
	}
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return false
	}
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(c[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	return strings.HasSuffix(p, "*") || pos == len(c)
}

func protectedPathMatch(pattern, path string) bool {
	path = normalizePathToken(path)
	if path == "" || containsShellExpansion(path) {
		return false
	}
	pattern = expandHome(pattern)
	path = expandHome(path)
	if ok, _ := filepath.Match(pattern, path); ok {
		return true
	}
	basePattern := filepath.Base(pattern)
	if basePattern != "*" && (pattern == basePattern || strings.HasPrefix(pattern, "~")) {
		if ok, _ := filepath.Match(basePattern, filepath.Base(path)); ok {
			return true
		}
	}
	if strings.Contains(pattern, string(filepath.Separator)) {
		absPattern, _ := filepath.Abs(pattern)
		absPath, _ := filepath.Abs(path)
		if ok, _ := filepath.Match(absPattern, absPath); ok {
			return true
		}
	}
	return false
}

func normalizePathToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, `"'`)
	token = strings.TrimRight(token, ".,:")
	if strings.HasPrefix(token, "file://") {
		token = strings.TrimPrefix(token, "file://")
	}
	if i := strings.IndexByte(token, '='); i >= 0 && i+1 < len(token) {
		candidate := token[i+1:]
		if strings.Contains(candidate, "/") || strings.HasPrefix(candidate, ".") {
			token = candidate
		}
	}
	return token
}

func containsShellExpansion(path string) bool {
	return strings.ContainsAny(path, "$`")
}

func defaultDenyCommands() []string {
	return []string{
		"rm -rf /",
		"rm -rf /*",
		"chmod -R 777 *",
		"chown -R *",
		"mkfs *",
		"dd if=* of=*",
		":(){ :|:& };:",
	}
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	if runtime.GOOS == "windows" {
		return filepath.FromSlash(p)
	}
	return p
}

func reasonForDeny(rule string) string {
	switch {
	case strings.Contains(rule, "rm -rf"):
		return "destructive removal"
	case strings.Contains(rule, "chmod") || strings.Contains(rule, "chown"):
		return "dangerous permission change"
	case strings.Contains(rule, "mkfs") || strings.Contains(rule, "dd if="):
		return "destructive disk operation"
	case strings.Contains(rule, "| bash") || strings.Contains(rule, "| sh"):
		return "dangerous pipe execution"
	default:
		return "denied command rule"
	}
}

func reasonForConfirm(rule string) string {
	if strings.HasPrefix(rule, "sudo") {
		return "sudo command"
	}
	return "sensitive command requires confirmation"
}
