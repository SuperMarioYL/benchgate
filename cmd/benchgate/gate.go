package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/benchgate/internal/config"
	"github.com/SuperMarioYL/benchgate/internal/detect"
	"github.com/SuperMarioYL/benchgate/internal/mocks"
)

// gateOptions carries the gate command flags.
type gateOptions struct {
	DryRun bool
	Listen string
}

// backupSuffix is the crash-safety copy of the original config: if the
// gate process is killed hard (SIGKILL, power loss) mid-eval, the
// operator still has the unmodified config on disk.
const backupSuffix = ".benchgate.bak"

func newGateCmd() *cobra.Command {
	var opts gateOptions
	cmd := &cobra.Command{
		Use:   "gate <config> -- <eval command>",
		Short: "Swap real gateway credentials for a local mock, then run the eval",
		Long: `Start a local mock gateway, rewrite the sandbox config so every real
credential value and gateway URL points at it, re-verify that no real
credential shape or real gateway reference remains, then run the eval
command. Afterwards the original config is restored.

The gate does not rely on network isolation: even with default public
egress, the model can only ever reach the mock, so no real quota is
spent and scores stay clean.

Use --dry-run to apply, verify and restore without starting the eval.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runGate(cmd, args[0], args[1:], opts)
		},
	}
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "apply and verify the mock rewrite, restore the config, and exit without running the eval")
	cmd.Flags().StringVar(&opts.Listen, "listen", "127.0.0.1:0", "address for the mock gateway to listen on")
	return cmd
}

// runGate is the m3 milestone: mock injection, config rewrite, re-verify
// zero real egress surfaces, then hand control to the eval.
func runGate(cmd *cobra.Command, configPath string, evalCmd []string, opts gateOptions) error {
	if !opts.DryRun && len(evalCmd) == 0 {
		return fmt.Errorf("gate needs the eval command after `--`, or --dry-run")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	envExposures := detect.ScanEnv(cfg.Env)
	for _, ex := range detect.ScanMounts(cfg.Mounts) {
		fmt.Fprintf(out, "gate: warning: mounted credential file %s cannot be auto-mocked; remove the mount\n", ex.Path)
	}
	if len(envExposures) == 0 {
		fmt.Fprintln(out, "gate: no credential findings in the config; nothing to mock")
		if opts.DryRun {
			return nil
		}
		code, runErr := runEval(evalCmd, nil)
		return finishEval(cmd, code, runErr)
	}

	gw, err := mocks.StartGateway(opts.Listen)
	if err != nil {
		return fmt.Errorf("start mock gateway: %w", err)
	}
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = gw.Stop(ctx)
	}

	replacements := mocks.PlanRewrite(cfg, gw.BaseURL())

	original, err := os.ReadFile(configPath)
	if err != nil {
		stop()
		return fmt.Errorf("read config for backup: %w", err)
	}
	backupPath := configPath + backupSuffix
	if err := os.WriteFile(backupPath, original, 0o644); err != nil {
		stop()
		return fmt.Errorf("write backup %s: %w", backupPath, err)
	}

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		_ = os.WriteFile(configPath, original, 0o644)
		_ = os.Remove(backupPath)
	}
	// Restore on every return path; exit paths call restore explicitly
	// first because os.Exit would skip defers.
	defer restore()

	if err := mocks.RewriteFile(configPath, configPath, replacements, gw.BaseURL()); err != nil {
		stop()
		return fmt.Errorf("rewrite config for mock gateway: %w", err)
	}

	patched, err := config.Load(configPath)
	if err != nil {
		stop()
		return fmt.Errorf("re-parse patched config: %w", err)
	}
	if problems := mocks.VerifyPatched(patched); len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(cmd.ErrOrStderr(), "gate: re-verify failed: %s\n", p)
		}
		stop()
		return fmt.Errorf("patched config still exposes real credentials; original config restored")
	}

	fmt.Fprintf(out, "gate: mock gateway at %s\n", gw.BaseURL())
	for _, r := range replacements {
		fmt.Fprintf(out, "  %-28s %s -> %s  (%s)\n", r.EnvVar, r.Kind, r.To, r.From)
	}
	fmt.Fprintln(out, "gate: re-verified — no real credential shapes and no real gateway endpoints remain in the patched config")

	if opts.DryRun {
		fmt.Fprintln(out, "gate: dry run complete — config restored, eval not started")
		stop()
		return nil
	}

	code, runErr := runEval(evalCmd, []string{"BENCHGATE_MOCK_URL=" + gw.BaseURL()})
	fmt.Fprintf(out, "gate: eval exited with code %d; mock gateway served %d request(s) during the eval\n", code, len(gw.Requests()))
	restore() // explicit: exitFunc below skips defers
	stop()
	return finishEval(cmd, code, runErr)
}

// finishEval maps an eval result to the benchgate exit code.
func finishEval(cmd *cobra.Command, code int, runErr error) error {
	if runErr != nil {
		return runErr
	}
	if code != 0 {
		exitFunc(code)
	}
	return nil
}

// runEval execs the eval command with stdio passed through, forwarding
// SIGINT/SIGTERM so an interrupted eval does not leave the config
// patched behind a dead benchgate process.
func runEval(evalCmd []string, extraEnv []string) (int, error) {
	c := exec.Command(evalCmd[0], evalCmd[1:]...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if len(extraEnv) > 0 {
		c.Env = append(os.Environ(), extraEnv...)
	}

	if err := c.Start(); err != nil {
		return 0, fmt.Errorf("start eval command: %w", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		if s, ok := <-sigs; ok && c.Process != nil {
			_ = c.Process.Signal(s)
		}
	}()

	err := c.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// The eval's own exit code is the gate's exit code.
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 0, fmt.Errorf("run eval command: %w", err)
	}
	return 0, nil
}
