package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/adminvirtmo/agentguard/internal/audit"
	"github.com/adminvirtmo/agentguard/internal/config"
	"github.com/adminvirtmo/agentguard/internal/doctor"
	"github.com/adminvirtmo/agentguard/internal/mcp"
	"github.com/adminvirtmo/agentguard/internal/memory"
	"github.com/adminvirtmo/agentguard/internal/report"
	"github.com/adminvirtmo/agentguard/internal/runner"
	"github.com/adminvirtmo/agentguard/internal/scanner"
)

var (
	configPath = config.DefaultPath
	auditDir   = "."
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "agentguard",
		Short:         "Local firewall and flight recorder for AI coding agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", config.DefaultPath, "path to AgentGuard YAML config")
	cmd.PersistentFlags().StringVar(&auditDir, "audit-dir", ".", "directory where .agentguard audit data is stored")
	cmd.AddCommand(initCmd(), runCmd(), timelineCmd(), reportCmd(), scanCmd(), memoryCmd(), doctorCmd(), mcpCmd())
	return cmd
}

func initCmd() *cobra.Command {
	var force bool
	var profile string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create agentguard.yml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !config.ValidProfile(profile) {
				return fmt.Errorf("--profile must be one of %s", strings.Join(config.ProfileNames(), ", "))
			}
			if _, err := os.Stat(configPath); err == nil && !force {
				return fmt.Errorf("%s already exists", configPath)
			}
			if err := config.WriteProfile(configPath, profile); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created %s using %s profile\n", configPath, profile)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config file")
	cmd.Flags().StringVar(&profile, "profile", config.ProfileBalanced, "policy profile: balanced, strict or permissive")
	return cmd
}

func runCmd() *cobra.Command {
	var shell bool
	cmd := &cobra.Command{
		Use:   "run -- <command>",
		Short: "Run a command through AgentGuard",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(configPath)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to load %s: %v\n", configPath, err)
				os.Exit(2)
			}
			store, err := audit.Open(auditDir)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to open audit store: %v\n", err)
				os.Exit(2)
			}
			defer store.Close()
			r := runner.Runner{Config: cfg, Audit: store, In: os.Stdin, Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr(), Shell: shell}
			os.Exit(r.Run(context.Background(), args))
		},
	}
	cmd.Flags().BoolVar(&shell, "shell", false, "execute the command through the local shell after policy checks")
	return cmd
}

func timelineCmd() *cobra.Command {
	var limit int
	var jsonOutput bool
	var status string
	var sinceValue string
	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "Show local command history",
		RunE: func(cmd *cobra.Command, args []string) error {
			status = strings.ToLower(status)
			if !audit.ValidStatus(status) {
				return fmt.Errorf("--status must be one of %s", strings.Join(audit.StatusNames(), ", "))
			}
			since, err := audit.ParseSince(sinceValue, time.Now())
			if err != nil {
				return err
			}
			store, err := audit.Open(auditDir)
			if err != nil {
				return err
			}
			defer store.Close()
			events, err := store.List(limit)
			if err != nil {
				return err
			}
			events = audit.Filter(events, status, since)
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(events)
			}
			for _, e := range events {
				t, _ := time.Parse(time.RFC3339, e.Timestamp)
				label := strings.ToUpper(e.Status)
				if len(label) < 9 {
					label += strings.Repeat(" ", 9-len(label))
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s %s\n", t.Local().Format("15:04"), label, e.Command)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum number of events to show")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print timeline as JSON")
	cmd.Flags().StringVar(&status, "status", "", "filter by status: allowed, blocked, confirmed, denied or failed")
	cmd.Flags().StringVar(&sinceValue, "since", "", "filter events since a duration, RFC3339 timestamp or YYYY-MM-DD date")
	return cmd
}

func reportCmd() *cobra.Command {
	var output string
	var sinceValue string
	var format string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate agentguard-report.md",
		RunE: func(cmd *cobra.Command, args []string) error {
			since, err := audit.ParseSince(sinceValue, time.Now())
			if err != nil {
				return err
			}
			store, err := audit.Open(auditDir)
			if err != nil {
				return err
			}
			defer store.Close()
			events, err := store.List(0)
			if err != nil {
				return err
			}
			events = audit.Filter(events, "", since)
			switch strings.ToLower(format) {
			case "markdown", "md":
				if err := report.Generate(events, output); err != nil {
					return err
				}
			case "json":
				if err := report.GenerateJSON(events, output); err != nil {
					return err
				}
			default:
				return fmt.Errorf("--format must be markdown or json")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", report.DefaultPath, "Markdown report path")
	cmd.Flags().StringVar(&sinceValue, "since", "", "include events since a duration, RFC3339 timestamp or YYYY-MM-DD date")
	cmd.Flags().StringVar(&format, "format", "markdown", "report format: markdown or json")
	return cmd
}

func scanCmd() *cobra.Command {
	var jsonOutput bool
	var failOn string
	var path string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan the current project for local security risks",
		RunE: func(cmd *cobra.Command, args []string) error {
			minSeverity := scanner.ParseSeverity(failOn)
			if failOn != "" && minSeverity == "" {
				return fmt.Errorf("--fail-on must be one of low, medium or high")
			}
			findings, err := scanner.Scan(path)
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(findings); err != nil {
					return err
				}
			} else {
				fmt.Fprint(cmd.OutOrStdout(), scanner.Format(findings))
			}
			if failOn != "" && scanner.HasSeverityAtLeast(findings, minSeverity) {
				return fmt.Errorf("scan found findings at or above %s", strings.ToUpper(failOn))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print findings as JSON")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero on severity low, medium or high")
	cmd.Flags().StringVar(&path, "path", ".", "directory to scan")
	return cmd
}

func memoryCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "memory",
		Short: "Manage safe project memory for AI agents",
	}
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export AGENTS.md",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := audit.Open(auditDir)
			if err != nil {
				return err
			}
			defer store.Close()
			events, err := store.List(0)
			if err != nil {
				return err
			}
			if err := memory.Export(events, output); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", output)
			return nil
		},
	}
	exportCmd.Flags().StringVarP(&output, "output", "o", memory.DefaultPath, "memory file path")
	cmd.AddCommand(exportCmd)
	return cmd
}

func doctorCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check AgentGuard local setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := doctor.Run(configPath, auditDir)
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(checks); err != nil {
					return err
				}
			} else {
				for _, check := range checks {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s - %s\n", strings.ToUpper(string(check.Status)), check.Name, check.Message)
					if check.Fix != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "     fix: %s\n", check.Fix)
					}
				}
			}
			if !doctor.Healthy(checks) {
				return fmt.Errorf("doctor found setup errors")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print checks as JSON")
	return cmd
}

func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Experimental MCP safety helpers",
	}
	var input string
	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a JSON MCP-like tool call against the local policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load %s: %w", configPath, err)
			}
			var payload []byte
			if input != "" {
				payload, err = os.ReadFile(input)
			} else {
				payload, err = io.ReadAll(os.Stdin)
			}
			if err != nil {
				return err
			}
			decision, err := mcp.Inspect(cfg, payload)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(decision); err != nil {
				return err
			}
			if decision.Status == "blocked" {
				return fmt.Errorf("MCP call blocked: %s", decision.Reason)
			}
			return nil
		},
	}
	inspectCmd.Flags().StringVarP(&input, "input", "i", "", "JSON file to inspect; stdin is used when empty")
	cmd.AddCommand(inspectCmd)
	return cmd
}
