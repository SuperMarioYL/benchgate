package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/benchgate/internal/config"
	"github.com/SuperMarioYL/benchgate/internal/detect"
	"github.com/SuperMarioYL/benchgate/internal/probe"
	"github.com/SuperMarioYL/benchgate/internal/report"
)

// auditOptions carries the audit command flags.
type auditOptions struct {
	JSON    bool
	Output  string
	Offline bool
}

func newAuditCmd() *cobra.Command {
	var opts auditOptions
	cmd := &cobra.Command{
		Use:   "audit <task.toml|config.yaml|docker-compose.yaml>",
		Short: "Report the credential surfaces an eval sandbox exposes to the model",
		Long: `Parse a Harbor task.toml, a job-level config.yaml or a compose file and
report the exposure ledger: which real credentials the model under test
can reach (env vars, bind-mounted files), whether their gateway endpoint
is reachable under the configured network policy, and the evidence behind
each verdict.

Credential values are never printed or written; entries are identified
by variable name, prefix class, length and a SHA-256 fingerprint.

Exit codes: 0 when the config is clean, 1 when any real credential is
model-reachable — wire the command directly into CI as a pre-bench gate.
The live endpoint check never sends credentials; --offline skips it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true // config errors are not usage errors
			return runAudit(cmd, args[0], opts)
		},
	}
	cmd.Flags().BoolVar(&opts.JSON, "json", false, "print the report as JSON to stdout")
	cmd.Flags().StringVar(&opts.Output, "output", "", "write the report to a file (.md renders Markdown, anything else JSON)")
	cmd.Flags().BoolVar(&opts.Offline, "offline", false, "skip the live endpoint check (no outbound HTTP from the audit host)")
	return cmd
}

// runAudit executes the full audit chain: parse, detect, probe, report,
// exit code. It is the whole m2 milestone in one call.
func runAudit(cmd *cobra.Command, path string, opts auditOptions) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	exposures := detect.ScanEnv(cfg.Env)
	exposures = append(exposures, detect.ScanMounts(cfg.Mounts)...)

	prober := probe.NewProber(opts.Offline, probe.DefaultTimeout)
	exposures = prober.Assess(cfg, exposures)

	rep := report.New(version, report.SourceInfo{Path: cfg.Source, Kind: cfg.Kind}, report.NetworkInfo{
		Mode:         cfg.NetworkMode,
		AllowedHosts: cfg.AllowedHosts,
	}, exposures)

	out := cmd.OutOrStdout()
	switch {
	case opts.JSON:
		blob, err := rep.JSON()
		if err != nil {
			return fmt.Errorf("render report: %w", err)
		}
		fmt.Fprintln(out, string(blob))
	case opts.Output != "":
		if err := writeReportFile(opts.Output, rep); err != nil {
			return err
		}
		report.RenderText(out, rep)
	default:
		report.RenderText(out, rep)
	}

	// The CI gate: findings > 0 fails the run. exitFunc (not a bare
	// return) so the exit code reaches CI even though cobra treats a
	// clean RunE return as success.
	if code := report.ExitCode(rep); code != 0 {
		exitFunc(code)
	}
	return nil
}

// writeReportFile writes the report to path; a .md extension renders
// Markdown, anything else JSON.
func writeReportFile(path string, rep *report.Report) error {
	var blob []byte
	var err error
	if strings.HasSuffix(strings.ToLower(path), ".md") {
		var sb strings.Builder
		report.RenderMarkdown(&sb, rep)
		blob = []byte(sb.String())
	} else {
		blob, err = rep.JSON()
		if err != nil {
			return fmt.Errorf("render report: %w", err)
		}
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		return fmt.Errorf("write report %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "report written to %s\n", path)
	return nil
}
