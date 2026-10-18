package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// m3 gate flow: mock injected, re-verified, eval executed, config
// restored byte-for-byte.
func TestGateRunsCommandAndRestoresConfig(t *testing.T) {
	path := writeDirtyConfig(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(t.TempDir(), "ran.txt")
	out, code, err := runRoot(t, "gate", path, "--", "sh", "-c", "echo ok > "+marker)
	if err != nil {
		t.Fatalf("gate failed: %v\n%s", err, out)
	}
	if code != nil {
		t.Fatalf("exit hook called with %d, want clean return", *code)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("eval command did not run: %v", err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Error("gate did not restore the original config")
	}
	if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
		t.Error("backup file left behind after clean gate run")
	}
	// Gate output must not leak the real key value either.
	if strings.Contains(out, "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Errorf("gate output leaked the credential value:\n%s", out)
	}
	if !strings.Contains(out, "re-verified") {
		t.Errorf("gate output missing re-verification line:\n%s", out)
	}
}

// The eval sees the mock URL through BENCHGATE_MOCK_URL and the mock
// answers; while the eval runs, the config on disk is the patched one.
func TestGateEvalHitsMockGateway(t *testing.T) {
	path := writeDirtyConfig(t)

	// The eval script calls the mock through the injected URL and
	// snapshots the config file it would be loaded from.
	dir := t.TempDir()
	mockRespFile := filepath.Join(dir, "mock-response.txt")
	snapshotFile := filepath.Join(dir, "snapshot.toml")
	script := "curl -s \"$BENCHGATE_MOCK_URL/models\" > " + mockRespFile + "; cat " + path + " > " + snapshotFile
	out, code, err := runRoot(t, "gate", path, "--", "sh", "-c", script)
	if err != nil {
		t.Fatalf("gate failed: %v\n%s", err, out)
	}
	if code != nil {
		t.Fatalf("exit hook called with %d, want clean return", *code)
	}

	blob, err := os.ReadFile(mockRespFile)
	if err != nil {
		t.Fatalf("eval did not reach the mock gateway: %v\n%s", err, out)
	}
	if !strings.Contains(string(blob), "benchgate-mock/mock-model") {
		t.Errorf("mock gateway response unexpected: %s", blob)
	}

	snapshot, err := os.ReadFile(snapshotFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapshot), "OPENROUTER_API_KEY = 'benchgate-mock-key'") {
		t.Errorf("patched config during eval missing mock key:\n%s", snapshot)
	}
	if !strings.Contains(string(snapshot), "http://127.0.0.1:") || strings.Contains(string(snapshot), "https://openrouter.ai") {
		t.Errorf("patched config during eval still references the real gateway:\n%s", snapshot)
	}

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restored), "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Error("original config not restored after gate run")
	}
}

// --dry-run applies and verifies the rewrite, then restores; nothing
// executes.
func TestGateDryRun(t *testing.T) {
	path := writeDirtyConfig(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	out, code, err := runRoot(t, "gate", "--dry-run", path)
	if err != nil {
		t.Fatalf("gate dry-run failed: %v\n%s", err, out)
	}
	if code != nil {
		t.Fatalf("exit hook called with %d, want clean return", *code)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Error("dry run did not restore the original config")
	}
	if !strings.Contains(out, "mock key") || !strings.Contains(out, "re-verified") {
		t.Errorf("dry-run output missing rewrite summary:\n%s", out)
	}
	if strings.Contains(out, "sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Errorf("dry-run output leaked the credential value:\n%s", out)
	}
}

// Gate on an already-clean config runs the eval ungated.
func TestGateCleanConfigPassthrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.yaml")
	if err := os.WriteFile(path, []byte("environment:\n  env:\n    MODEL_PORT: \"8080\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code, err := runRoot(t, "gate", path, "--", "true")
	if err != nil {
		t.Fatalf("gate failed: %v\n%s", err, out)
	}
	if code != nil {
		t.Fatalf("exit hook called with %d, want clean return", *code)
	}
	if !strings.Contains(out, "nothing to mock") {
		t.Errorf("gate output missing nothing-to-mock line:\n%s", out)
	}
}

func TestGateRequiresEvalCommand(t *testing.T) {
	path := writeDirtyConfig(t)
	_, _, err := runRoot(t, "gate", path)
	if err == nil || !strings.Contains(err.Error(), "--dry-run") {
		t.Errorf("err = %v, want missing-eval-command error", err)
	}
}

// The eval's own exit code becomes the gate's exit code.
func TestGatePropagatesEvalExitCode(t *testing.T) {
	path := writeDirtyConfig(t)
	out, code, err := runRoot(t, "gate", path, "--", "sh", "-c", "exit 3")
	if err != nil {
		t.Fatalf("gate failed: %v\n%s", err, out)
	}
	if code == nil || *code != 3 {
		t.Fatalf("exit code = %v, want 3", code)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restored), "sk-or-v1-") {
		t.Error("config not restored after failing eval")
	}
}
