package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
	if rule := firstMatch(cfg.Deny.Commands, cmd); rule != "" {
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
		clean := strings.Trim(arg, `"'`)
		for _, pattern := range patterns {
			if protectedPathMatch(pattern, clean) && !seen[clean] {
				found = append(found, clean)
				seen[clean] = true
			}
		}
	}
	return found
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
