package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/adminvirtmo/agentguard/internal/audit"
	"github.com/adminvirtmo/agentguard/internal/config"
	"github.com/adminvirtmo/agentguard/internal/memory"
	"github.com/adminvirtmo/agentguard/internal/report"
	"github.com/adminvirtmo/agentguard/internal/runner"
	"github.com/adminvirtmo/agentguard/internal/scanner"
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
	cmd.AddCommand(initCmd(), runCmd(), timelineCmd(), reportCmd(), scanCmd(), memoryCmd())
	return cmd
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create agentguard.yml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(config.DefaultPath); err == nil {
				return fmt.Errorf("%s already exists", config.DefaultPath)
			}
			if err := config.WriteDefault(config.DefaultPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created %s\n", config.DefaultPath)
			return nil
		},
	}
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run -- <command>",
		Short: "Run a command through AgentGuard",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(config.DefaultPath)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to load %s: %v\n", config.DefaultPath, err)
				os.Exit(2)
			}
			store, err := audit.Open(".")
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "failed to open audit store: %v\n", err)
				os.Exit(2)
			}
			defer store.Close()
			r := runner.Runner{Config: cfg, Audit: store, In: os.Stdin, Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr()}
			os.Exit(r.Run(context.Background(), args))
		},
	}
}

func timelineCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "timeline",
		Short: "Show local command history",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := audit.Open(".")
			if err != nil {
				return err
			}
			defer store.Close()
			events, err := store.List(0)
			if err != nil {
				return err
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
}

func reportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Generate agentguard-report.md",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := audit.Open(".")
			if err != nil {
				return err
			}
			defer store.Close()
			events, err := store.List(0)
			if err != nil {
				return err
			}
			if err := report.Generate(events, report.DefaultPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", report.DefaultPath)
			return nil
		},
	}
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan the current project for local security risks",
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := scanner.Scan(".")
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), scanner.Format(findings))
			return nil
		},
	}
}

func memoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "memory",
		Short: "Manage safe project memory for AI agents",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "export",
		Short: "Export AGENTS.md",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := audit.Open(".")
			if err != nil {
				return err
			}
			defer store.Close()
			events, err := store.List(0)
			if err != nil {
				return err
			}
			if err := memory.Export(events, memory.DefaultPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", memory.DefaultPath)
			return nil
		},
	})
	return cmd
}
