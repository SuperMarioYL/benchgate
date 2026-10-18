// Command benchgate audits eval sandbox configs for credentials the model
// under test can reach, and gates eval runs behind mock gateways.
//
//	benchgate audit task.toml   # exposure ledger + exit-code gate
//	benchgate gate task.toml -- <eval command>
//
// This file owns the command wiring. The audit engine (credential
// detection, in-container probing, report and exit codes) lands in
// audit.go, and the mock gateway injection lands in gate.go.
package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/benchgate/internal/config"
)

// version is the released version; release builds override it with
// -ldflags "-X main.version=<tag>". Keep in sync with the VERSION file.
var version = "0.1.0"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "benchgate",
		Short:   "Pre-bench credential audit and mock gateway gate for eval sandboxes",
		Version: version,
		Long: `BenchGate audits Harbor/Pier eval sandbox configs before a benchmark run
and reports which real credentials (env vars, mounted files, compose
arguments) the model under test can reach, then gate swaps them for
mock gateways so the eval can proceed without burning real quota.`,
	}
	root.AddCommand(newAuditCmd(), newGateCmd())
	return root
}

func newAuditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit <task.toml|config.yaml|docker-compose.yaml>",
		Short: "List the credential surfaces an eval sandbox exposes to the model",
		Long: `Parse a Harbor task.toml, a job-level config.yaml or a compose file and
print the sandbox surfaces the model under test can reach: injected env
vars, network policy and host bind mounts. Values are never printed.

The full audit engine (credential shape detection, in-container probing,
exposure ledger and CI exit codes) lands with the audit implementation.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true // config errors are not usage errors
			cfg, err := config.Load(args[0])
			if err != nil {
				return err
			}
			return printSurfacePreview(cmd.OutOrStdout(), cfg)
		},
	}
}

// printSurfacePreview reports what the parser sees. Variable names only:
// the audit's own contract is that secret values never reach disk or
// output.
func printSurfacePreview(w io.Writer, cfg *config.SandboxConfig) error {
	fmt.Fprintf(w, "source: %s (%s)\n", cfg.Source, cfg.Kind)
	fmt.Fprintf(w, "network_mode: %s\n", cfg.NetworkMode)
	if len(cfg.AllowedHosts) > 0 {
		fmt.Fprintf(w, "allowed_hosts: %s\n", strings.Join(cfg.AllowedHosts, ", "))
	}

	names := make([]string, 0, len(cfg.Env))
	for name := range cfg.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "env vars: %d (values withheld)\n", len(names))
	for _, name := range names {
		fmt.Fprintf(w, "  %s\n", name)
	}

	fmt.Fprintf(w, "mounts: %d\n", len(cfg.Mounts))
	for _, m := range cfg.Mounts {
		mode := "rw"
		if m.ReadOnly {
			mode = "ro"
		}
		fmt.Fprintf(w, "  %s -> %s (%s)\n", m.HostPath, m.ContainerPath, mode)
	}

	fmt.Fprintf(w, "\ncredential detection, in-container probing and the exposure ledger land with the audit engine\n")
	return nil
}

func newGateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gate <task.toml|config.yaml|docker-compose.yaml> -- <eval command>",
		Short: "Swap real gateway credentials for mock endpoints, then run the eval",
		Long: `Start a local mock gateway that mirrors the real one, rewrite the sandbox
config to point at it, re-verify that the model can reach zero real
credentials, then run the eval command. Scores stay clean and no real
quota is spent.

The mock gateway and re-verification land with the gate implementation.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return fmt.Errorf("gate: not implemented yet — the mock gateway lands with the gate implementation")
		},
	}
}
