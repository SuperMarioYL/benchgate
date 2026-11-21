package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// taskTomlDefaultPublic mirrors the Harbor hello-world example shape
// (schema_version 1.1, [task]/[metadata]/[agent]/[verifier]/[environment])
// with the gateway keys the audit scenario injects via [environment.env].
// No network_mode is set: Harbor defaults to public.
const taskTomlDefaultPublic = `
schema_version = "1.1"

[task]
name = "harbor/hello-world"
description = "Verifies that environment.env reaches the initial process."
keywords = ["environment", "startup", "runtime"]

[metadata]
author_name = "The Harbor Authors"
author_email = "hello@laude.org"
difficulty = "easy"
category = "test"
tags = ["environment", "startup", "single-container"]

[agent]
timeout_sec = 30.0

[verifier]
timeout_sec = 30.0

[verifier.env]
VERIFIER_TOKEN = "verifier-side-only"

[environment]
build_timeout_sec = 120.0
cpus = 1
memory_mb = 512
storage_mb = 1024

[environment.env]
OPENROUTER_API_KEY = "sk-or-v1-0123456789abcdef0123456789abcdef"
MODELSCOPE_SDK_TOKEN = "ms-11111111-2222-3333-4444-555555555555"
PROVIDER_BASE_URL = "${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}"
`

func TestLoadTaskTomlDefaultsToPublic(t *testing.T) {
	cfg, err := LoadTaskToml(writeTemp(t, "task.toml", taskTomlDefaultPublic))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != KindTaskToml {
		t.Errorf("Kind = %q, want %q", cfg.Kind, KindTaskToml)
	}
	if cfg.NetworkMode != NetworkPublic {
		t.Errorf("NetworkMode = %q, want default %q", cfg.NetworkMode, NetworkPublic)
	}
	want := map[string]string{
		"OPENROUTER_API_KEY":   "sk-or-v1-0123456789abcdef0123456789abcdef",
		"MODELSCOPE_SDK_TOKEN": "ms-11111111-2222-3333-4444-555555555555",
		"PROVIDER_BASE_URL":    "${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}",
	}
	if !reflect.DeepEqual(cfg.Env, want) {
		t.Errorf("Env = %v, want %v", cfg.Env, want)
	}
	// Verifier-side env must not surface: the verifier is not the model
	// container.
	if _, ok := cfg.Env["VERIFIER_TOKEN"]; ok {
		t.Error("Env leaked [verifier.env]; verifier secrets are not model-reachable")
	}
	if len(cfg.AllowedHosts) != 0 {
		t.Errorf("AllowedHosts = %v, want empty for non-allowlist mode", cfg.AllowedHosts)
	}
}

// The [agent] phase override wins over the [environment] baseline: the
// agent phase is where the model under test runs.
const taskTomlAgentAllowlist = `
schema_version = "1.1"

[agent]
timeout_sec = 30.0
network_mode = "allowlist"
allowed_hosts = ["openrouter.ai", "*.modelscope.cn"]

[environment]
network_mode = "no-network"
cpus = 1

[environment.env]
OPENROUTER_API_KEY = "sk-or-v1-deadbeef"
`

func TestLoadTaskTomlAgentPhaseOverride(t *testing.T) {
	cfg, err := LoadTaskToml(writeTemp(t, "task.toml", taskTomlAgentAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkMode != NetworkAllowlist {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, NetworkAllowlist)
	}
	wantHosts := []string{"openrouter.ai", "*.modelscope.cn"}
	if !reflect.DeepEqual(cfg.AllowedHosts, wantHosts) {
		t.Errorf("AllowedHosts = %v, want %v", cfg.AllowedHosts, wantHosts)
	}
	if cfg.Env["OPENROUTER_API_KEY"] != "sk-or-v1-deadbeef" {
		t.Errorf("Env[OPENROUTER_API_KEY] = %q", cfg.Env["OPENROUTER_API_KEY"])
	}
}

func TestLoadTaskTomlNoNetworkBaseline(t *testing.T) {
	cfg, err := LoadTaskToml(writeTemp(t, "task.toml", `
[agent]
timeout_sec = 30.0

[environment]
network_mode = "no-network"

[environment.env]
OPENROUTER_API_KEY = "sk-or-v1-isolated"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkMode != NetworkNone {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, NetworkNone)
	}
	if len(cfg.AllowedHosts) != 0 {
		t.Errorf("AllowedHosts = %v, want empty", cfg.AllowedHosts)
	}
}

// allow_internet = false is the pre-network_mode spelling; harbor still
// migrates it, so the loader honors it too.
func TestLoadTaskTomlLegacyAllowInternet(t *testing.T) {
	cfg, err := LoadTaskToml(writeTemp(t, "task.toml", `
[environment]
allow_internet = false

[environment.env]
OPENAI_API_KEY = "sk-legacy"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkMode != NetworkNone {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, NetworkNone)
	}
	if cfg.Env["OPENAI_API_KEY"] != "sk-legacy" {
		t.Errorf("Env[OPENAI_API_KEY] = %q", cfg.Env["OPENAI_API_KEY"])
	}
}

const jobConfigYAML = `
environment:
  network_mode: no-network
  env:
    OPENROUTER_API_KEY: sk-or-v1-job-level
    MODEL_PORT: 8080
agents:
  - name: terminus-2
tasks:
  - path: tasks/hello-world
`

func TestLoadJobConfig(t *testing.T) {
	cfg, err := LoadJobConfig(writeTemp(t, "config.yaml", jobConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != KindJobYAML {
		t.Errorf("Kind = %q, want %q", cfg.Kind, KindJobYAML)
	}
	if cfg.NetworkMode != NetworkNone {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, NetworkNone)
	}
	want := map[string]string{
		"OPENROUTER_API_KEY": "sk-or-v1-job-level",
		"MODEL_PORT":         "8080",
	}
	if !reflect.DeepEqual(cfg.Env, want) {
		t.Errorf("Env = %v, want %v", cfg.Env, want)
	}
}

func TestLoadJobConfigWithoutEnvironment(t *testing.T) {
	cfg, err := LoadJobConfig(writeTemp(t, "config.yaml", `
agents:
  - name: nop
tasks:
  - path: tasks/hello-world
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkMode != NetworkPublic {
		t.Errorf("NetworkMode = %q, want default %q", cfg.NetworkMode, NetworkPublic)
	}
	if len(cfg.Env) != 0 {
		t.Errorf("Env = %v, want empty", cfg.Env)
	}
}

const composeUnionYAML = `
services:
  main:
    environment:
      OPENROUTER_API_KEY: sk-or-v1-in-main
    volumes:
      - ./fixtures:/workspace/fixtures:ro
      - shared-cache:/var/cache
  sidecar:
    image: alpine:3.21
    environment:
      - SIDECAR_TOKEN=ms-sidecar
      - PASSTHROUGH_TOKEN
      - EMPTY=
    network_mode: none
    volumes:
      - ./shared:/srv/shared
volumes:
  shared-cache:
`

func TestLoadCompose(t *testing.T) {
	cfg, err := LoadCompose(writeTemp(t, "docker-compose.yaml", composeUnionYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kind != KindCompose {
		t.Errorf("Kind = %q, want %q", cfg.Kind, KindCompose)
	}
	// Union across services: sidecars share the compose network with the
	// model container, so their env vars are in scope too.
	want := map[string]string{
		"OPENROUTER_API_KEY": "sk-or-v1-in-main",
		"SIDECAR_TOKEN":      "ms-sidecar",
		"PASSTHROUGH_TOKEN":  "",
		"EMPTY":              "",
	}
	if !reflect.DeepEqual(cfg.Env, want) {
		t.Errorf("Env = %v, want %v", cfg.Env, want)
	}
	// Named volume shared-cache is not a host path and must be skipped.
	wantMounts := []Mount{
		{HostPath: "./fixtures", ContainerPath: "/workspace/fixtures", ReadOnly: true},
		{HostPath: "./shared", ContainerPath: "/srv/shared", ReadOnly: false},
	}
	if !reflect.DeepEqual(cfg.Mounts, wantMounts) {
		t.Errorf("Mounts = %v, want %v", cfg.Mounts, wantMounts)
	}
	// The main service sets no network_mode: compose defaults to egress.
	if cfg.NetworkMode != NetworkPublic {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, NetworkPublic)
	}
}

func TestLoadComposeAllIsolated(t *testing.T) {
	cfg, err := LoadCompose(writeTemp(t, "docker-compose.yaml", `
services:
  main:
    network_mode: none
  sidecar:
    network_mode: none
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NetworkMode != NetworkNone {
		t.Errorf("NetworkMode = %q, want %q", cfg.NetworkMode, NetworkNone)
	}
	if len(cfg.Env) != 0 {
		t.Errorf("Env = %v, want empty", cfg.Env)
	}
}

func TestLoadComposeWithoutServices(t *testing.T) {
	_, err := LoadCompose(writeTemp(t, "docker-compose.yaml", `
version: "3"
`))
	if err == nil || !strings.Contains(err.Error(), "no services") {
		t.Errorf("err = %v, want no-services error", err)
	}
}

func TestLoadDispatch(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		kind string
	}{
		{"task toml", "task.toml", taskTomlDefaultPublic, KindTaskToml},
		{"compose by services key", "compose.yaml", composeUnionYAML, KindCompose},
		{"job yaml", "config.yaml", jobConfigYAML, KindJobYAML},
		{"yml extension", "config.yml", jobConfigYAML, KindJobYAML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, tc.file, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", cfg.Kind, tc.kind)
			}
		})
	}
}

func TestLoadUnsupportedExtension(t *testing.T) {
	_, err := Load(writeTemp(t, "config.json", `{"environment": {}}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported config format") {
		t.Errorf("err = %v, want unsupported-format error", err)
	}
}

func TestLoadTaskTomlErrors(t *testing.T) {
	if _, err := LoadTaskToml("/nonexistent/task.toml"); err == nil {
		t.Error("missing file: want error, got nil")
	}
	_, err := LoadTaskToml(writeTemp(t, "task.toml", "schema_version = [unclosed"))
	if err == nil || !strings.Contains(err.Error(), "parse task config") {
		t.Errorf("err = %v, want parse error naming the file", err)
	}
}

// compose env_file injects credentials the same way inline environment
// does; the loader must read it and remember which names came from it.
func TestLoadComposeReadsEnvFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gw.env"), []byte(`
# gateway credentials
export MODELSCOPE_SDK_TOKEN="ms-11111111-2222-3333-4444-555555555555"
PLAIN=value
`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte(`
services:
  main:
    env_file:
      - ./gw.env
    environment:
      OPENROUTER_API_KEY: sk-or-v1-inline
`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"MODELSCOPE_SDK_TOKEN": "ms-11111111-2222-3333-4444-555555555555",
		"PLAIN":                "value",
		"OPENROUTER_API_KEY":   "sk-or-v1-inline",
	}
	if !reflect.DeepEqual(cfg.Env, want) {
		t.Errorf("Env = %v, want %v", cfg.Env, want)
	}
	wantVars := []string{"MODELSCOPE_SDK_TOKEN", "PLAIN"}
	if !reflect.DeepEqual(cfg.EnvFileVars, wantVars) {
		t.Errorf("EnvFileVars = %v, want %v", cfg.EnvFileVars, wantVars)
	}
}

// A declared env_file that cannot be read must fail the load: skipping it
// would hide every credential it injects.
func TestLoadComposeMissingEnvFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte(`
services:
  main:
    env_file: ./gone.env
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCompose(path)
	if err == nil || !strings.Contains(err.Error(), "gone.env") {
		t.Errorf("err = %v, want an env_file error naming the path", err)
	}
}

// Compose expands ${VAR} on the host before mounting, so an interpolated
// source is still a host bind mount and must not be dropped.
func TestParseBindMountInterpolatedHost(t *testing.T) {
	m, ok := parseBindMount("${HOME}/.aws/credentials:/root/.aws/credentials:ro")
	if !ok {
		t.Fatal("interpolated host mount was dropped")
	}
	if m.HostPath != "${HOME}/.aws/credentials" || m.ContainerPath != "/root/.aws/credentials" || !m.ReadOnly {
		t.Errorf("Mount = %+v", m)
	}
}

func TestParseBindMountStillSkipsNamedVolumes(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"shared-cache:/var/cache", false},
		{"data:/data:ro", false},
		{"/abs/path:/x", true},
		{"./rel/path:/x", true},
		{"${HOME}/.aws/credentials:/root/.aws/credentials:ro", true},
	}
	for _, tc := range cases {
		if _, ok := parseBindMount(tc.spec); ok != tc.want {
			t.Errorf("parseBindMount(%q) = %t, want %t", tc.spec, ok, tc.want)
		}
	}
}

// The full loader must surface an interpolated mount; only the literal
// sibling used to be reported.
func TestLoadComposeInterpolatedMount(t *testing.T) {
	cfg, err := LoadCompose(writeTemp(t, "docker-compose.yaml", `
services:
  main:
    volumes:
      - "${HOME}/.aws/credentials:/root/.aws/credentials:ro"
      - "shared-cache:/var/cache"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Mount{{HostPath: "${HOME}/.aws/credentials", ContainerPath: "/root/.aws/credentials", ReadOnly: true}}
	if !reflect.DeepEqual(cfg.Mounts, want) {
		t.Errorf("Mounts = %v, want %v", cfg.Mounts, want)
	}
}
