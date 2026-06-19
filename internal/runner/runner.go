package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/adminvirtmo/agentguard/internal/audit"
	"github.com/adminvirtmo/agentguard/internal/config"
	"github.com/adminvirtmo/agentguard/internal/policy"
)

type Runner struct {
	Config config.Config
	Audit  *audit.Store
	In     io.Reader
	Out    io.Writer
	Err    io.Writer
}

func (r Runner) Run(ctx context.Context, args []string) int {
	if r.In == nil {
		r.In = os.Stdin
	}
	if r.Out == nil {
		r.Out = os.Stdout
	}
	if r.Err == nil {
		r.Err = os.Stderr
	}
	start := time.Now()
	decision := policy.Evaluate(r.Config, args)
	switch decision.Status {
	case policy.StatusBlocked:
		fmt.Fprintf(r.Out, "BLOCKED: %s\nReason: %s\n", blockedMessage(decision), decision.Reason)
		r.log(args, string(policy.StatusBlocked), decision.Reason, 126, time.Since(start), decision.SensitiveFiles)
		return 126
	case policy.StatusConfirm:
		fmt.Fprintf(r.Out, "CONFIRMATION REQUIRED\nCommand: %s\nReason: %s\nAllow? [y/N] ", strings.Join(args, " "), decision.Reason)
		if !confirm(r.In) {
			fmt.Fprintln(r.Out, "DENIED")
			r.log(args, string(policy.StatusDenied), decision.Reason, 126, time.Since(start), decision.SensitiveFiles)
			return 126
		}
		code := r.exec(ctx, args)
		status := string(policy.StatusConfirmed)
		if code != 0 {
			status = string(policy.StatusFailed)
		}
		r.log(args, status, decision.Reason, code, time.Since(start), decision.SensitiveFiles)
		return code
	default:
		code := r.exec(ctx, args)
		status := string(policy.StatusAllowed)
		reason := decision.Reason
		if code != 0 {
			status = string(policy.StatusFailed)
			reason = "command failed"
		}
		r.log(args, status, reason, code, time.Since(start), decision.SensitiveFiles)
		return code
	}
}

func (r Runner) exec(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(r.Err, "no command provided")
		return 2
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = r.In
	cmd.Stdout = r.Out
	cmd.Stderr = r.Err
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(r.Err, "failed to run command: %v\n", err)
		return 127
	}
	return 0
}

func (r Runner) log(args []string, status, reason string, code int, dur time.Duration, sensitive []string) {
	if r.Audit == nil {
		return
	}
	_ = r.Audit.Add(audit.NewEvent(args, status, reason, code, dur, sensitive))
}

func confirm(in io.Reader) bool {
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}

func blockedMessage(d policy.Decision) string {
	if len(d.SensitiveFiles) > 0 {
		return fmt.Sprintf("access to protected file %q", d.SensitiveFiles[0])
	}
	if d.MatchedRule != "" {
		return fmt.Sprintf("command matched deny rule %q", d.MatchedRule)
	}
	return d.Reason
}
