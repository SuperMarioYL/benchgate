// Command benchgate audits eval sandbox configs for credentials the model
// under test can reach, and gates eval runs behind mock gateways.
//
//	benchgate audit task.toml   # exposure ledger + exit-code gate
//	benchgate gate task.toml -- <eval command>
//
// This file owns the command wiring: the audit engine lives in audit.go
// and the mock gateway injection in gate.go.
package main

import (
	"os"

	"github.com/spf13/cobra"
)

// version is the released version; release builds override it with
// -ldflags "-X main.version=<tag>". Keep in sync with the VERSION file.
var version = "0.1.0"

// exitFunc is the process exit hook, swappable in tests so commands can
// assert their CI exit codes.
var exitFunc = os.Exit

func main() {
	if err := newRootCmd().Execute(); err != nil {
		exitFunc(1)
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
