package mocks

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/SuperMarioYL/benchgate/internal/config"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const mockURL = "http://127.0.0.1:65500/api/v1"

// TestRewriteTaskTomlRoundTrip gates a Harbor task.toml and verifies the
// rewrite touches nothing but the credential surfaces: unknown tables,
// verifier-side env and benign vars survive byte-for-byte in meaning.
func TestRewriteTaskTomlRoundTrip(t *testing.T) {
	src := writeTemp(t, "task.toml", `
schema_version = "1.1"

[task]
name = "demo-task"

[verifier.env]
VERIFIER_TOKEN = "verifier-side-only"

[environment]
network_mode = "public"

[environment.env]
OPENROUTER_API_KEY = "sk-or-v1-0123456789abcdef0123456789abcdef"
OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
PROVIDER_BASE_URL = "${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}"
KEEP_ME = "untouched"
`)
	cfg, err := config.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	replacements := PlanRewrite(cfg, mockURL)
	if len(replacements) != 3 {
		t.Fatalf("PlanRewrite = %d replacements, want 3 (key + direct URL + template URL)", len(replacements))
	}

	dst := filepath.Join(t.TempDir(), "patched.toml")
	if err := RewriteFile(src, dst, replacements, mockURL); err != nil {
		t.Fatal(err)
	}

	patched, err := config.Load(dst)
	if err != nil {
		t.Fatal(err)
	}
	wantEnv := map[string]string{
		"OPENROUTER_API_KEY": MockKeyValue,
		"OPENAI_BASE_URL":    mockURL,
		"PROVIDER_BASE_URL":  mockURL,
		"KEEP_ME":            "untouched",
	}
	for k, want := range wantEnv {
		if patched.Env[k] != want {
			t.Errorf("patched Env[%q] = %q, want %q", k, patched.Env[k], want)
		}
	}
	if _, ok := patched.Env["VERIFIER_TOKEN"]; ok {
		t.Error("rewrite touched [verifier.env]; verifier secrets are not model-reachable")
	}

	// Structure beyond environment.env survives the round-trip.
	var tree map[string]any
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	task, _ := tree["task"].(map[string]any)
	if task == nil || task["name"] != "demo-task" {
		t.Errorf("[task] table lost in rewrite: %v", tree["task"])
	}
	verifier, _ := tree["verifier"].(map[string]any)
	if venv, _ := verifier["env"].(map[string]any); venv == nil || venv["VERIFIER_TOKEN"] != "verifier-side-only" {
		t.Errorf("[verifier.env] lost in rewrite: %v", tree["verifier"])
	}
	if patched.NetworkMode != config.NetworkPublic {
		t.Errorf("NetworkMode = %q, want %q", patched.NetworkMode, config.NetworkPublic)
	}
}

// The gate's re-verification: a patched config must have no real
// credential shapes and no real gateway references; an unpatched one
// must fail verification.
func TestVerifyPatched(t *testing.T) {
	clean := &config.SandboxConfig{Env: map[string]string{
		"OPENROUTER_API_KEY": MockKeyValue,
		"OPENAI_BASE_URL":    mockURL,
		"MODEL_PORT":         "8080",
	}}
	if problems := VerifyPatched(clean); len(problems) != 0 {
		t.Errorf("VerifyPatched(clean) = %v, want none", problems)
	}

	dirty := &config.SandboxConfig{Env: map[string]string{
		"OPENROUTER_API_KEY": "sk-or-v1-0123456789abcdef0123456789abcdef",
		"OPENAI_BASE_URL":    "https://openrouter.ai/api/v1",
	}}
	problems := VerifyPatched(dirty)
	if len(problems) != 2 {
		t.Fatalf("VerifyPatched(dirty) = %v, want 2 problems", problems)
	}
	for _, p := range problems {
		if strings.Contains(p, "sk-or-v1-0123456789abcdef0123456789abcdef") {
			t.Errorf("verification problem leaked a value: %s", p)
		}
	}
}

func TestRewriteJobYAML(t *testing.T) {
	src := writeTemp(t, "config.yaml", `
agents:
  - name: terminus-2
tasks:
  - path: tasks/hello-world
environment:
  network_mode: no-network
  env:
    OPENROUTER_API_KEY: sk-or-v1-0123456789abcdef0123456789abcdef
    MODEL_PORT: 8080
`)
	cfg, err := config.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	replacements := PlanRewrite(cfg, mockURL)
	if len(replacements) != 1 {
		t.Fatalf("PlanRewrite = %d replacements, want 1", len(replacements))
	}
	dst := filepath.Join(t.TempDir(), "patched.yaml")
	if err := RewriteFile(src, dst, replacements, mockURL); err != nil {
		t.Fatal(err)
	}
	patched, err := config.Load(dst)
	if err != nil {
		t.Fatal(err)
	}
	if patched.Env["OPENROUTER_API_KEY"] != MockKeyValue {
		t.Errorf("patched key = %q", patched.Env["OPENROUTER_API_KEY"])
	}
	if patched.Env["MODEL_PORT"] != "8080" {
		t.Errorf("patched MODEL_PORT = %q, want untouched", patched.Env["MODEL_PORT"])
	}
	if patched.NetworkMode != config.NetworkNone {
		t.Errorf("NetworkMode = %q, want %q", patched.NetworkMode, config.NetworkNone)
	}
}

// Compose list-form env includes bare passthrough names; the gate turns
// them into explicit mock values so host resolution cannot inject a real
// key at runtime.
func TestRewriteComposeListForm(t *testing.T) {
	src := writeTemp(t, "docker-compose.yaml", `
services:
  main:
    environment:
      - OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef
      - PASSTHROUGH_TOKEN
      - MODEL_PORT=8080
`)
	cfg, err := config.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	replacements := PlanRewrite(cfg, mockURL)
	if len(replacements) != 2 {
		t.Fatalf("PlanRewrite = %d replacements, want 2", len(replacements))
	}
	dst := filepath.Join(t.TempDir(), "patched.yaml")
	if err := RewriteFile(src, dst, replacements, mockURL); err != nil {
		t.Fatal(err)
	}
	patched, err := config.Load(dst)
	if err != nil {
		t.Fatal(err)
	}
	if patched.Env["OPENROUTER_API_KEY"] != MockKeyValue {
		t.Errorf("patched key = %q", patched.Env["OPENROUTER_API_KEY"])
	}
	if patched.Env["PASSTHROUGH_TOKEN"] != MockKeyValue {
		t.Errorf("patched passthrough = %q, want explicit mock value", patched.Env["PASSTHROUGH_TOKEN"])
	}
	if patched.Env["MODEL_PORT"] != "8080" {
		t.Errorf("patched MODEL_PORT = %q, want untouched", patched.Env["MODEL_PORT"])
	}
}

func TestRewriteMissingVarFails(t *testing.T) {
	src := writeTemp(t, "task.toml", `
[environment.env]
KEEP_ME = "untouched"
`)
	replacements := []Replacement{{EnvVar: "GHOST_VAR", Kind: ReplCredentialValue, To: "mock key"}}
	dst := filepath.Join(t.TempDir(), "patched.toml")
	err := RewriteFile(src, dst, replacements, mockURL)
	if err == nil || !strings.Contains(err.Error(), "GHOST_VAR") {
		t.Errorf("err = %v, want missing-var error naming GHOST_VAR", err)
	}
}

func TestRewriteUnsupportedFormat(t *testing.T) {
	src := writeTemp(t, "config.json", `{"environment": {"env": {}}}`)
	err := RewriteFile(src, filepath.Join(t.TempDir(), "out.json"), nil, mockURL)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("err = %v, want unsupported-format error", err)
	}
}

func TestPlanRewriteDescriptionsCarryNoValues(t *testing.T) {
	cfg := &config.SandboxConfig{Env: map[string]string{
		"OPENROUTER_API_KEY": "sk-or-v1-live-value-0123456789abcdef",
		"OPENAI_BASE_URL":    "https://openrouter.ai/api/v1",
	}}
	replacements := PlanRewrite(cfg, mockURL)
	blob, err := json.Marshal(replacements)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "sk-or-v1-live-value-0123456789abcdef") {
		t.Errorf("replacement plan leaked the credential value: %s", blob)
	}
	var sawKey, sawURL bool
	for _, r := range replacements {
		switch r.EnvVar {
		case "OPENROUTER_API_KEY":
			sawKey = true
			if r.Kind != ReplCredentialValue {
				t.Errorf("kind = %q", r.Kind)
			}
		case "OPENAI_BASE_URL":
			sawURL = true
			if r.Kind != ReplGatewayURL || r.To != mockURL {
				t.Errorf("kind/to = %q/%q", r.Kind, r.To)
			}
		}
	}
	if !sawKey || !sawURL {
		t.Errorf("missing replacements: %+v", replacements)
	}
}

// TestGatewayEndpoints exercises the mock surface: provider-shaped
// responses on the routes harnesses call, 404 elsewhere, and a request
// log that records method/path/status but never headers.
func TestGatewayEndpoints(t *testing.T) {
	gw, err := StartGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = gw.Stop(ctx)
	}()

	base := gw.BaseURL()
	if !strings.HasPrefix(base, "http://127.0.0.1:") || !strings.HasSuffix(base, "/api/v1") {
		t.Fatalf("BaseURL = %q", base)
	}

	// models
	resp, err := http.Get(base + "/models")
	if err != nil {
		t.Fatal(err)
	}
	var models struct {
		Data []struct{ ID string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || len(models.Data) != 1 || !strings.Contains(models.Data[0].ID, "mock") {
		t.Errorf("models: status=%d body=%+v", resp.StatusCode, models)
	}

	// chat completions
	post, err := http.Post(base+"/chat/completions", "application/json", strings.NewReader(`{"model":"deepseek/v4.1-flash","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var chat struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(post.Body).Decode(&chat); err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != 200 || chat.Model != "deepseek/v4.1-flash" || len(chat.Choices) != 1 ||
		chat.Choices[0].Message.Role != "assistant" || chat.Usage.TotalTokens != 0 {
		t.Errorf("chat completions: status=%d body=%+v", post.StatusCode, chat)
	}

	// key info (OpenRouter shape)
	resp2, err := http.Get(base + "/key")
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&key); err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 || key.Label != "benchgate-mock" {
		t.Errorf("key: status=%d label=%q", resp2.StatusCode, key.Label)
	}

	// unknown endpoint: fast provider-shaped 404
	resp3, err := http.Get(base + "/api/v1/unknown")
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 404 {
		t.Errorf("unknown endpoint status = %d, want 404", resp3.StatusCode)
	}

	// health
	resp4, err := http.Get(strings.TrimSuffix(base, "/api/v1") + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != 200 {
		t.Errorf("health status = %d", resp4.StatusCode)
	}

	logs := gw.Requests()
	if len(logs) != 5 {
		t.Fatalf("request log = %d entries, want 5", len(logs))
	}
	for _, l := range logs {
		if l.Method == "" || l.Path == "" || l.Status == 0 {
			t.Errorf("incomplete request log entry: %+v", l)
		}
	}
}

// The mock must be bound to the loopback interface only.
func TestGatewayBindsLoopback(t *testing.T) {
	gw, err := StartGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = gw.Stop(ctx)
	}()
	if !strings.HasPrefix(gw.Addr(), "127.0.0.1:") {
		t.Errorf("Addr = %q, want loopback bind", gw.Addr())
	}
}
