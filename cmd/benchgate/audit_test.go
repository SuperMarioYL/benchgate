package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runRoot executes the root command with the given args, stubbing the
// process exit hook so tests can observe exit codes without dying.
func runRoot(t *testing.T, args ...string) (string, *int, error) {
	t.Helper()
	var code *int
	old := exitFunc
	exitFunc = func(c int) { cc := c; code = &cc }
	defer func() { exitFunc = old }()

	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), code, err
}

const dirtyTaskTOML = `
schema_version = "1.1"

[task]
name = "demo-task"

[environment]
network_mode = "public"

[environment.env]
OPENROUTER_API_KEY = "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef"
OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
`

func writeDirtyConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "task.toml")
	if err := os.WriteFile(path, []byte(dirtyTaskTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// m2 acceptance: the example task reports the OpenRouter key exposure
// and exits 1; the cleaned variant exits 0. --offline keeps the tests
// hermetic (the live check would call the real gateway).
func TestAuditDirtyExitsOne(t *testing.T) {
	path := writeDirtyConfig(t)
	out, code, err := runRoot(t, "audit", "--offline", path)
	if err != nil {
		t.Fatalf("audit failed: %v\n%s", err, out)
	}
	if code == nil || *code != 1 {
		t.Fatalf("exit code = %v, want 1", code)
	}
	if !strings.Contains(out, "OPENROUTER_API_KEY") || !strings.Contains(out, "openrouter") {
		t.Errorf("audit output missing the finding:\n%s", out)
	}
	// The no-value contract: the key value must not appear anywhere.
	if strings.Contains(out, "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Errorf("audit output leaked the credential value:\n%s", out)
	}
	if !strings.Contains(out, "sha256:") {
		t.Errorf("audit output missing fingerprint:\n%s", out)
	}
}

func TestAuditCleanExitsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.yaml")
	if err := os.WriteFile(path, []byte(`
environment:
  network_mode: public
  env:
    OPENAI_BASE_URL: "https://openrouter.ai/api/v1"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code, err := runRoot(t, "audit", "--offline", path)
	if err != nil {
		t.Fatalf("audit failed: %v\n%s", err, out)
	}
	if code != nil {
		t.Errorf("exit hook called with %d, want clean return", *code)
	}
	if !strings.Contains(out, "findings: 0") {
		t.Errorf("audit output missing clean summary:\n%s", out)
	}
}

func TestAuditJSONFlag(t *testing.T) {
	path := writeDirtyConfig(t)
	out, code, err := runRoot(t, "audit", "--json", "--offline", path)
	if err != nil {
		t.Fatalf("audit failed: %v\n%s", err, out)
	}
	if code == nil || *code != 1 {
		t.Fatalf("exit code = %v, want 1", code)
	}
	var doc struct {
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
		Findings []struct {
			Path    string `json:"path"`
			Gateway string `json:"gateway"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if doc.Summary.Total != 1 || len(doc.Findings) != 1 || doc.Findings[0].Path != "OPENROUTER_API_KEY" {
		t.Errorf("unexpected JSON report: %s", out)
	}
}

func TestAuditOutputFile(t *testing.T) {
	path := writeDirtyConfig(t)
	reportPath := filepath.Join(t.TempDir(), "report.md")
	out, code, err := runRoot(t, "audit", "--offline", "--output", reportPath, path)
	if err != nil {
		t.Fatalf("audit failed: %v\n%s", err, out)
	}
	if code == nil || *code != 1 {
		t.Fatalf("exit code = %v, want 1", code)
	}
	blob, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "# BenchGate exposure ledger") {
		t.Errorf("markdown report missing header:\n%s", blob)
	}
}

func TestAuditBadConfig(t *testing.T) {
	out, _, err := runRoot(t, "audit", "/nonexistent/task.toml")
	if err == nil {
		t.Errorf("want error for missing config, got none\n%s", out)
	}
}
