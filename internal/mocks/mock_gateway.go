// Package mocks implements the gate mechanism: a local HTTP gateway that
// mirrors the provider API surface (OpenAI-compatible, which both
// OpenRouter and ModelScope speak), and the config rewrite that points
// the sandbox at it instead of the real gateway.
//
// The gate does not rely on network isolation. With the real key and the
// real base URL replaced, every gateway call the model can make lands on
// the local mock even when the container has full egress, so no real
// quota can be spent and scores stay clean.
package mocks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	yaml "gopkg.in/yaml.v3"

	"github.com/SuperMarioYL/benchgate/internal/config"
	"github.com/SuperMarioYL/benchgate/internal/detect"
	"github.com/SuperMarioYL/benchgate/internal/report"
)

// MockKeyValue is the placeholder credential the gate writes into the
// config. It is deliberately not shaped like a real key (no sk-/ms-/
// Bearer prefix) so re-detection does not flag it as a real credential.
const MockKeyValue = "benchgate-mock-key"

// Replacement kinds.
const (
	ReplCredentialValue = "credential_value"
	ReplGatewayURL      = "gateway_url"
)

// Replacement records one env var the gate rewrote. From is a sanitized
// description (detection source, fingerprint or referenced host) — never
// the original value.
type Replacement struct {
	EnvVar string `json:"env_var"`
	Kind   string `json:"kind"`
	From   string `json:"from"`
	To     string `json:"to"`
}

// PlanRewrite computes the env-var replacements that gate the config:
// every detected credential value becomes the mock key, and every value
// referencing a real gateway host becomes the mock base URL.
func PlanRewrite(cfg *config.SandboxConfig, mockBaseURL string) []Replacement {
	byName := map[string]report.Exposure{}
	for _, ex := range detect.ScanEnv(cfg.Env) {
		byName[ex.Path] = ex
	}

	names := make([]string, 0, len(cfg.Env))
	for name := range cfg.Env {
		names = append(names, name)
	}
	sort.Strings(names)

	replacements := make([]Replacement, 0, len(names))
	for _, name := range names {
		if ex, ok := byName[name]; ok {
			replacements = append(replacements, Replacement{
				EnvVar: name,
				Kind:   ReplCredentialValue,
				From:   fmt.Sprintf("%s; %s", ex.Source, ex.Fingerprint),
				To:     "mock key",
			})
			continue
		}
		if gateway := detect.GatewayForHost(cfg.Env[name]); gateway != detect.GatewayUnknown {
			replacements = append(replacements, Replacement{
				EnvVar: name,
				Kind:   ReplGatewayURL,
				From:   fmt.Sprintf("references gateway host %s", detect.GatewayHost(gateway)),
				To:     mockBaseURL,
			})
		}
	}
	return replacements
}

// RewriteFile rewrites the credential surfaces of a config file in
// place within the file's own format. It re-parses the raw document as a
// generic tree and mutates only the env values named by the
// replacements, so unknown tables ([task], [metadata], [verifier], ...)
// survive untouched.
func RewriteFile(srcPath, dstPath string, replacements []Replacement, mockBaseURL string) error {
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read config %s: %w", srcPath, err)
	}

	byVar := make(map[string]Replacement, len(replacements))
	for _, r := range replacements {
		byVar[r.EnvVar] = r
	}
	applied := make(map[string]bool, len(replacements))

	switch strings.ToLower(filepath.Ext(srcPath)) {
	case ".toml":
		err = rewriteTOML(raw, dstPath, byVar, mockBaseURL, applied)
	case ".yaml", ".yml":
		err = rewriteYAML(raw, dstPath, byVar, mockBaseURL, applied)
	default:
		err = fmt.Errorf("unsupported config format %q in %s", filepath.Ext(srcPath), srcPath)
	}
	if err != nil {
		return err
	}

	var missing []string
	for name := range byVar {
		if !applied[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("rewrite did not find these env vars in %s: %s", srcPath, strings.Join(missing, ", "))
	}
	return nil
}

func rewriteTOML(raw []byte, dstPath string, byVar map[string]Replacement, mockBaseURL string, applied map[string]bool) error {
	var tree map[string]any
	if err := toml.Unmarshal(raw, &tree); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	envTable, err := nestedStringMap(tree, "environment", "env")
	if err != nil {
		return fmt.Errorf("no [environment.env] table to rewrite: %w", err)
	}
	applyToMap(envTable, byVar, mockBaseURL, applied)
	out, err := toml.Marshal(tree)
	if err != nil {
		return fmt.Errorf("re-emit config: %w", err)
	}
	return os.WriteFile(dstPath, out, 0o644)
}

func rewriteYAML(raw []byte, dstPath string, byVar map[string]Replacement, mockBaseURL string, applied map[string]bool) error {
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if _, isCompose := tree["services"]; isCompose {
		services, err := nestedStringMap(tree, "services")
		if err != nil {
			return fmt.Errorf("no services table to rewrite: %w", err)
		}
		serviceNames := make([]string, 0, len(services))
		for name := range services {
			serviceNames = append(serviceNames, name)
		}
		sort.Strings(serviceNames)
		for _, name := range serviceNames {
			svc, ok := services[name].(map[string]any)
			if !ok {
				continue
			}
			switch env := svc["environment"].(type) {
			case map[string]any:
				applyToMap(env, byVar, mockBaseURL, applied)
			case []any:
				applyToList(env, byVar, mockBaseURL, applied)
			}
		}
		return os.WriteFile(dstPath, marshalYAML(tree), 0o644)
	}

	envTable, err := nestedStringMap(tree, "environment", "env")
	if err != nil {
		return fmt.Errorf("no environment.env table to rewrite: %w", err)
	}
	applyToMap(envTable, byVar, mockBaseURL, applied)
	return os.WriteFile(dstPath, marshalYAML(tree), 0o644)
}

// applyToMap replaces the values of matched env vars in a map-form env
// table.
func applyToMap(envTable map[string]any, byVar map[string]Replacement, mockBaseURL string, applied map[string]bool) {
	for name := range envTable {
		repl, ok := byVar[name]
		if !ok {
			continue
		}
		envTable[name] = replacementValue(repl, mockBaseURL)
		applied[name] = true
	}
}

// applyToList replaces matched env vars in compose list form, including
// bare passthrough names ("KEY" with no "=").
func applyToList(items []any, byVar map[string]Replacement, mockBaseURL string, applied map[string]bool) {
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(s, "=")
		repl, ok := byVar[name]
		if !ok {
			continue
		}
		items[i] = name + "=" + replacementValue(repl, mockBaseURL)
		applied[name] = true
	}
}

func replacementValue(repl Replacement, mockBaseURL string) string {
	if repl.Kind == ReplGatewayURL {
		return mockBaseURL
	}
	return MockKeyValue
}

// nestedStringMap walks a generic document tree down a path of map keys.
func nestedStringMap(tree map[string]any, path ...string) (map[string]any, error) {
	cur := tree
	for _, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("missing table %q", key)
		}
		cur = next
	}
	return cur, nil
}

// marshalYAML emits a generic tree back to YAML. yaml.v3 marshals
// map[string]any with keys sorted, so output is deterministic.
func marshalYAML(tree map[string]any) []byte {
	out, err := yaml.Marshal(tree)
	if err != nil {
		// Marshal of an already-decoded tree cannot fail in practice;
		// fall back to the empty document rather than panicking.
		return []byte("")
	}
	return out
}

// VerifyPatched re-checks a loaded patched config: no value may still
// match a real credential shape, and no value may still reference a real
// gateway host. Returns one human-readable problem per violation (names
// only, never values).
func VerifyPatched(cfg *config.SandboxConfig) []string {
	var problems []string
	for _, ex := range detect.ScanEnv(cfg.Env) {
		if ex.Source == detect.SourceValueShape {
			problems = append(problems, fmt.Sprintf("%s still matches a real credential shape (%s)", ex.Path, ex.Fingerprint))
		}
	}
	names := make([]string, 0, len(cfg.Env))
	for name := range cfg.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if gateway := detect.GatewayForHost(cfg.Env[name]); gateway != detect.GatewayUnknown {
			problems = append(problems, fmt.Sprintf("%s still references the real %s gateway host %s", name, gateway, detect.GatewayHost(gateway)))
		}
	}
	return problems
}

// RequestLog records one request the mock gateway served. Headers are
// deliberately not recorded: the Authorization header carries whatever
// key the caller holds.
type RequestLog struct {
	Method string
	Path   string
	Status int
	At     time.Time
}

// Gateway is the local mock provider. Its handlers mirror the
// OpenAI-compatible surface both supported gateways speak.
type Gateway struct {
	server   *http.Server
	listener net.Listener

	mu       sync.Mutex
	requests []RequestLog
}

// StartGateway binds addr ("host:port", port 0 for an ephemeral port)
// on the loopback interface and serves until Stop.
func StartGateway(addr string) (*Gateway, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	g := &Gateway{listener: ln}
	g.server = &http.Server{
		Handler:           g.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = g.server.Serve(ln) }()
	return g, nil
}

// Addr returns the bound "host:port".
func (g *Gateway) Addr() string { return g.listener.Addr().String() }

// BaseURL returns the mock's API base URL to write into the config.
func (g *Gateway) BaseURL() string { return "http://" + g.Addr() + "/api/v1" }

// Requests returns the request log recorded so far.
func (g *Gateway) Requests() []RequestLog {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]RequestLog, len(g.requests))
	copy(out, g.requests)
	return out
}

// Stop shuts the server down and releases the port.
func (g *Gateway) Stop(ctx context.Context) error {
	return g.server.Shutdown(ctx)
}

func (g *Gateway) record(r *http.Request, status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, RequestLog{
		Method: r.Method,
		Path:   r.URL.Path,
		Status: status,
		At:     time.Now(),
	})
}

func (g *Gateway) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		g.record(r, http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","gateway":"benchgate-mock"}`)
	})

	mux.HandleFunc("GET /api/v1/models", func(w http.ResponseWriter, r *http.Request) {
		g.record(r, http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{
			"object": "list",
			"data": []map[string]any{{
				"id":       "benchgate-mock/mock-model",
				"object":   "model",
				"owned_by": "benchgate-mock",
			}},
		})
	})

	mux.HandleFunc("POST /api/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		model := requestModel(r)
		g.record(r, http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{
			"id":     "chatcmpl-benchgate-mock",
			"object": "chat.completion",
			"model":  model,
			"choices": []map[string]any{{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": "[benchgate-mock] This response came from the local mock gateway; no real provider was called.",
				},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		})
	})

	mux.HandleFunc("POST /api/v1/completions", func(w http.ResponseWriter, r *http.Request) {
		model := requestModel(r)
		g.record(r, http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{
			"id":     "cmpl-benchgate-mock",
			"object": "text_completion",
			"model":  model,
			"choices": []map[string]any{{
				"index":         0,
				"text":          "[benchgate-mock] no real completion is served during gated evals",
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		})
	})

	mux.HandleFunc("GET /api/v1/key", func(w http.ResponseWriter, r *http.Request) {
		g.record(r, http.StatusOK)
		writeJSON(w, http.StatusOK, map[string]any{
			"label":        "benchgate-mock",
			"usage":        0,
			"limit":        nil,
			"is_free_tier": true,
		})
	})

	// Anything else: provider-shaped 404 so clients fail fast instead of
	// hanging on an endpoint the mock never fakes.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		g.record(r, http.StatusNotFound)
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]any{
				"message": "benchgate mock gateway: no such endpoint",
				"code":    http.StatusNotFound,
			},
		})
	})

	return mux
}

// requestModel extracts the "model" field from a completion request
// body, tolerating malformed bodies. The body itself is never logged.
func requestModel(r *http.Request) string {
	var body struct {
		Model string `json:"model"`
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if err != nil || body.Model == "" {
		return "benchgate-mock/mock-model"
	}
	return body.Model
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
