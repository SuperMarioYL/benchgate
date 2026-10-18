// Package report renders the credential exposure ledger produced by an
// audit run: which real credentials the model under test can reach, how
// the sandbox network policy treats their gateways, and the evidence
// behind each verdict. It also owns the CI exit-code contract.
//
// The ledger never carries credential values. Every entry identifies a
// secret by variable name, prefix class, length and a SHA-256 fingerprint
// (see internal/detect), so reports can be archived and diffed without
// ever persisting the secrets themselves.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Surface kinds an exposure can be attached to.
const (
	SurfaceEnv         = "env"
	SurfaceMountedFile = "mounted_file"
	SurfaceComposeArg  = "compose_arg"
)

// Evidence kinds recorded on an exposure.
const (
	EvidencePolicy    = "policy"
	EvidenceHTTPProbe = "http_no_auth"
	EvidenceMount     = "mount"
)

// SourceInfo identifies the audited config file.
type SourceInfo struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// NetworkInfo is the effective network policy the model container runs
// under.
type NetworkInfo struct {
	Mode         string   `json:"mode"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}

// Summary is the roll-up the CI gate keys on.
type Summary struct {
	Total     int `json:"total"`
	Reachable int `json:"reachable"`
}

// ProbeRecord is one piece of evidence behind a Reachable verdict.
// Detail strings are built from variable names, policies, hosts and
// status codes only — never credential values.
type ProbeRecord struct {
	Kind       string `json:"kind"`
	Detail     string `json:"detail"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// Exposure is one model-reachable credential in the ledger.
type Exposure struct {
	// Fingerprint is a redacted identifier: prefix class, value length
	// and a SHA-256 prefix. Empty means no concrete value was present in
	// the config (host-side resolution at runtime).
	Fingerprint string `json:"fingerprint"`
	// Surface is one of the Surface* constants.
	Surface string `json:"surface"`
	// Path is the env var name, or the host file path for mounts.
	Path string `json:"path"`
	// Gateway is openrouter | modelscope | unknown.
	Gateway string `json:"gateway"`
	// Reachable is whether the credential's gateway endpoint is
	// reachable from the sandbox under the configured network policy
	// (for mounts: whether the file's bytes are readable in the
	// container).
	Reachable bool `json:"reachable"`
	// Resolved is true when the config carried a concrete value that
	// could be fingerprinted; false for host-side templates and
	// passthroughs.
	Resolved bool `json:"resolved"`
	// Source is how the credential was detected: value_shape | var_name
	// | mount_name.
	Source string `json:"source"`
	// Evidence holds the probe records behind Reachable.
	Evidence []ProbeRecord `json:"evidence,omitempty"`
}

// Report is the full audit result.
type Report struct {
	Tool        string      `json:"tool"`
	Version     string      `json:"version"`
	GeneratedAt string      `json:"generated_at"`
	Source      SourceInfo  `json:"source"`
	Network     NetworkInfo `json:"network"`
	Summary     Summary     `json:"summary"`
	Findings    []Exposure  `json:"findings"`
}

// New assembles a report and computes its summary. It always returns a
// non-nil Findings slice so JSON output renders [] instead of null.
func New(version string, src SourceInfo, net NetworkInfo, exposures []Exposure) *Report {
	if exposures == nil {
		exposures = []Exposure{}
	}
	rep := &Report{
		Tool:        "benchgate",
		Version:     version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      src,
		Network:     net,
		Findings:    exposures,
	}
	for _, ex := range exposures {
		rep.Summary.Total++
		if ex.Reachable {
			rep.Summary.Reachable++
		}
	}
	return rep
}

// ExitCode implements the CI contract: any finding fails the gate.
// Exit 1 means "real credentials are model-reachable"; 0 means the
// config is clean. The per-finding Reachable verdicts are carried in the
// report for humans, but the exit code stays binary so the gate cannot
// drift into policy-dependent interpretations.
func ExitCode(r *Report) int {
	if r.Summary.Total > 0 {
		return 1
	}
	return 0
}

// JSON renders the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// RenderText writes the human-readable ledger.
func RenderText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "benchgate %s — credential exposure ledger\n", r.Version)
	fmt.Fprintf(w, "config: %s (%s)\n", r.Source.Path, r.Source.Kind)
	fmt.Fprintf(w, "network: %s\n", r.Network.Mode)
	if len(r.Network.AllowedHosts) > 0 {
		fmt.Fprintf(w, "allowed_hosts: %s\n", strings.Join(r.Network.AllowedHosts, ", "))
	}
	fmt.Fprintf(w, "findings: %d (reachable: %d)\n\n", r.Summary.Total, r.Summary.Reachable)

	if r.Summary.Total == 0 {
		fmt.Fprintln(w, "no model-reachable credentials in this config")
		return
	}

	for i := range r.Findings {
		ex := &r.Findings[i]
		fmt.Fprintf(w, "[%d] %s\n", i+1, ex.Path)
		fmt.Fprintf(w, "    surface=%s  gateway=%s  reachable=%t\n", ex.Surface, ex.Gateway, ex.Reachable)
		fmt.Fprintf(w, "    detected=%s  resolved=%t\n", ex.Source, ex.Resolved)
		if ex.Fingerprint != "" {
			fmt.Fprintf(w, "    fingerprint: %s\n", ex.Fingerprint)
		}
		for _, ev := range ex.Evidence {
			fmt.Fprintf(w, "      - %s: %s\n", ev.Kind, ev.Detail)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "remediation: remove the real keys from the sandbox config, or run")
	fmt.Fprintf(w, "  benchgate gate %s -- <eval command>\n", r.Source.Path)
	fmt.Fprintln(w, "to swap them for a local mock gateway before the eval starts.")
}

// RenderMarkdown writes the ledger as a Markdown report file.
func RenderMarkdown(w io.Writer, r *Report) {
	fmt.Fprintf(w, "# BenchGate exposure ledger\n\n")
	fmt.Fprintf(w, "- config: `%s` (%s)\n", r.Source.Path, r.Source.Kind)
	fmt.Fprintf(w, "- network: `%s`\n", r.Network.Mode)
	if len(r.Network.AllowedHosts) > 0 {
		fmt.Fprintf(w, "- allowed_hosts: `%s`\n", strings.Join(r.Network.AllowedHosts, "`, `"))
	}
	fmt.Fprintf(w, "- findings: %d (reachable: %d)\n\n", r.Summary.Total, r.Summary.Reachable)

	if r.Summary.Total == 0 {
		fmt.Fprintln(w, "No model-reachable credentials in this config.")
		return
	}

	fmt.Fprintln(w, "| # | surface | path | gateway | reachable | fingerprint |")
	fmt.Fprintln(w, "|---|---------|------|---------|-----------|-------------|")
	for i := range r.Findings {
		ex := &r.Findings[i]
		fmt.Fprintf(w, "| %d | %s | `%s` | %s | %t | `%s` |\n",
			i+1, ex.Surface, ex.Path, ex.Gateway, ex.Reachable, ex.Fingerprint)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Evidence")
	fmt.Fprintln(w)
	for i := range r.Findings {
		ex := &r.Findings[i]
		fmt.Fprintf(w, "### %s\n\n", ex.Path)
		fmt.Fprintf(w, "- detected: %s (resolved=%t)\n", ex.Source, ex.Resolved)
		for _, ev := range ex.Evidence {
			fmt.Fprintf(w, "- %s: %s\n", ev.Kind, ev.Detail)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Credential values are never included in this report; entries are identified by name, prefix class, length and SHA-256 fingerprint only.")
}
