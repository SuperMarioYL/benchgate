// Package config parses the sandbox-facing parts of eval harness
// configuration: a Harbor/Pier task.toml, a Harbor job-level config.yaml,
// or a docker-compose file. Everything it returns is a surface the model
// under test can potentially reach once the eval starts: environment
// variables injected into the container, the network policy that decides
// whether those variables can be spent against a real gateway, and host
// directories bind-mounted into the sandbox.
//
// Harbor's schema is the reference (task.toml schema_version >= 1.1 with
// [environment.env] string pairs and a network_mode of "public",
// "no-network" or "allowlist", defaulting to public). Parsing is tolerant:
// unknown tables and fields are ignored rather than rejected, so Pier and
// self-built harness configs with the same shape parse too.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	yaml "gopkg.in/yaml.v3"
)

// Which loader produced a SandboxConfig.
const (
	KindTaskToml = "task_toml"
	KindJobYAML  = "job_yaml"
	KindCompose  = "compose"
)

// Normalized network policies. The audit treats anything not explicitly
// isolated as public: the model container is assumed to have egress unless
// the harness config says otherwise.
const (
	NetworkPublic    = "public"
	NetworkNone      = "none"
	NetworkAllowlist = "allowlist"
)

// mainServiceName is the compose service convention Harbor uses for the
// model/agent container (harbor.constants.MAIN_SERVICE_NAME).
const mainServiceName = "main"

// Mount is a host path bind-mounted into the sandbox. Named volumes carry
// no host file surface and are not reported.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// SandboxConfig is the set of model-reachable surfaces parsed from one
// config file. Env values are passed through verbatim (including ${VAR}
// host template placeholders) so credential detection can run on them;
// this package never redacts or resolves values.
type SandboxConfig struct {
	// Source is the file path the config was loaded from.
	Source string
	// Kind is one of the Kind* constants.
	Kind string
	// Env maps variable name to raw value for every env var the sandbox
	// config injects.
	Env map[string]string
	// NetworkMode is the normalized policy: NetworkPublic, NetworkNone or
	// NetworkAllowlist. Defaults to NetworkPublic.
	NetworkMode string
	// AllowedHosts is only populated when NetworkMode is NetworkAllowlist.
	AllowedHosts []string
	// Mounts are the host bind mounts; only compose configs carry mounts.
	Mounts []Mount
}

// Load parses a config file, picking the loader from the file extension.
// .toml is a Harbor task.toml. YAML is ambiguous between a job-level
// config.yaml and a compose file, so the top-level keys decide: a
// "services" key means compose.
func Load(path string) (*SandboxConfig, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		return LoadTaskToml(path)
	case ".yaml", ".yml":
		return LoadYAML(path)
	default:
		return nil, fmt.Errorf("unsupported config format %q in %s (want .toml, .yaml or .yml)", filepath.Ext(path), path)
	}
}

// LoadYAML sniffs a YAML file and dispatches to the job config or compose
// loader.
func LoadYAML(path string) (*SandboxConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var probe map[string]any
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if _, ok := probe["services"]; ok {
		return loadComposeRaw(path, raw)
	}
	return loadJobYAMLRaw(path, raw)
}

// LoadTaskToml parses a Harbor task.toml. The effective network policy is
// the [agent] phase override when set (that is the phase the model under
// test runs in), falling back to the [environment] baseline.
func LoadTaskToml(path string) (*SandboxConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read task config %s: %w", path, err)
	}
	var file taskTomlFile
	if err := toml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse task config %s: %w", path, err)
	}

	networkMode := file.Environment.NetworkMode
	allowedHosts := file.Environment.AllowedHosts
	if file.Agent.NetworkMode != "" {
		networkMode = file.Agent.NetworkMode
		allowedHosts = file.Agent.AllowedHosts
	}
	// Legacy shim still honored by harbor: allow_internet = false means
	// no-network when network_mode is unset.
	if networkMode == "" && file.Environment.AllowInternet != nil && !*file.Environment.AllowInternet {
		networkMode = "no-network"
	}

	return &SandboxConfig{
		Source:       path,
		Kind:         KindTaskToml,
		Env:          normalizeEnv(file.Environment.Env),
		NetworkMode:  normalizeNetworkMode(networkMode),
		AllowedHosts: allowedHosts,
	}, nil
}

// LoadJobConfig parses a Harbor job-level config.yaml. Only the job's
// [environment] section creates sandbox surfaces; per-agent network phase
// overrides are an audit-time refinement and are ignored here.
func LoadJobConfig(path string) (*SandboxConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read job config %s: %w", path, err)
	}
	return loadJobYAMLRaw(path, raw)
}

func loadJobYAMLRaw(path string, raw []byte) (*SandboxConfig, error) {
	var file jobYAMLFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse job config %s: %w", path, err)
	}
	if file.Environment == nil {
		return &SandboxConfig{
			Source:      path,
			Kind:        KindJobYAML,
			Env:         map[string]string{},
			NetworkMode: NetworkPublic,
		}, nil
	}

	networkMode := file.Environment.NetworkMode
	if networkMode == "" && file.Environment.AllowInternet != nil && !*file.Environment.AllowInternet {
		networkMode = "no-network"
	}
	return &SandboxConfig{
		Source:       path,
		Kind:         KindJobYAML,
		Env:          normalizeEnv(file.Environment.Env),
		NetworkMode:  normalizeNetworkMode(networkMode),
		AllowedHosts: file.Environment.AllowedHosts,
	}, nil
}

// LoadCompose parses a docker-compose file. Env vars are the union across
// services: the model container shares the compose network with the
// sidecars, so a credential parked in any service env is in scope. Mounts
// are the bind mounts across services; named volumes are skipped.
func LoadCompose(path string) (*SandboxConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compose file %s: %w", path, err)
	}
	return loadComposeRaw(path, raw)
}

func loadComposeRaw(path string, raw []byte) (*SandboxConfig, error) {
	var file composeFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse compose file %s: %w", path, err)
	}
	if len(file.Services) == 0 {
		return nil, fmt.Errorf("compose file %s defines no services", path)
	}

	names := make([]string, 0, len(file.Services))
	for name := range file.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	cfg := &SandboxConfig{
		Source:      path,
		Kind:        KindCompose,
		Env:         map[string]string{},
		NetworkMode: NetworkNone,
	}
	anyEgress := false
	for _, name := range names {
		svc := file.Services[name]

		switch env := svc.Environment.(type) {
		case map[string]any:
			for k, v := range normalizeEnv(env) {
				cfg.Env[k] = v
			}
		case []any:
			for _, item := range env {
				kv, ok := item.(string)
				if !ok {
					continue
				}
				// "KEY" alone is a host passthrough; the name is still a
				// surface even though the value is unknown here.
				k, val, _ := strings.Cut(kv, "=")
				if k != "" {
					cfg.Env[k] = val
				}
			}
		}

		for _, spec := range svc.Volumes {
			if m, ok := parseBindMount(spec); ok {
				cfg.Mounts = append(cfg.Mounts, m)
			}
		}

		mode, _ := svc.NetworkMode.(string)
		if normalizeNetworkMode(mode) != NetworkNone {
			anyEgress = true
		}
	}
	// Conservative: if any service can leave the compose network, treat
	// the whole sandbox as public.
	if anyEgress {
		cfg.NetworkMode = NetworkPublic
	}
	return cfg, nil
}

// taskTomlFile mirrors the parts of a Harbor task.toml that create
// surfaces. Unknown tables ([task], [metadata], [verifier], [solution],
// ...) are deliberately not modeled and are ignored by the parser.
//
// [verifier].env is intentionally absent: verifier-side env vars never
// reach the model container.
type taskTomlFile struct {
	SchemaVersion string       `toml:"schema_version"`
	Agent         phaseSection `toml:"agent"`
	Environment   envSection   `toml:"environment"`
}

// phaseSection is the [agent] network phase override.
type phaseSection struct {
	NetworkMode  string   `toml:"network_mode"`
	AllowedHosts []string `toml:"allowed_hosts"`
}

// envSection is shared between the TOML [environment] table and the YAML
// job config "environment" key.
type envSection struct {
	NetworkMode   string         `toml:"network_mode" yaml:"network_mode"`
	AllowInternet *bool          `toml:"allow_internet" yaml:"allow_internet"`
	AllowedHosts  []string       `toml:"allowed_hosts" yaml:"allowed_hosts"`
	Env           map[string]any `toml:"env" yaml:"env"`
}

type jobYAMLFile struct {
	Environment *envSection `yaml:"environment"`
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	// Environment is either a map (KEY: value) or a list (KEY=value).
	Environment any      `yaml:"environment"`
	Volumes     []string `yaml:"volumes"`
	NetworkMode any      `yaml:"network_mode"`
}

// normalizeNetworkMode maps harness and compose vocabulary onto the three
// audit policies. Unknown or empty modes resolve to public: the audit must
// assume egress unless isolation is explicit.
func normalizeNetworkMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "no-network", "none":
		return NetworkNone
	case "allowlist":
		return NetworkAllowlist
	default:
		// "", "public", "bridge", "host", custom networks: egress allowed.
		return NetworkPublic
	}
}

// normalizeEnv flattens scalar env values to strings. A nil value means a
// name-only entry (compose host passthrough) and is kept with an empty
// value; arrays and nested tables are not environment values and are
// dropped.
func normalizeEnv(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "" {
			continue
		}
		if v == nil {
			out[k] = ""
			continue
		}
		switch v.(type) {
		case string, bool,
			int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64,
			float32, float64:
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

// parseBindMount parses a compose volume spec into a Mount, keeping only
// host bind mounts ("/abs" or "./rel" sources). Named volumes and
// anonymous ("container-only") volumes carry no host file surface.
func parseBindMount(spec string) (Mount, bool) {
	parts := strings.Split(spec, ":")
	var host, container, mode string
	switch len(parts) {
	case 2:
		host, container = parts[0], parts[1]
	case 3:
		host, container, mode = parts[0], parts[1], parts[2]
	default:
		return Mount{}, false
	}
	if host == "" || container == "" {
		return Mount{}, false
	}
	if !strings.HasPrefix(host, "/") && !strings.HasPrefix(host, ".") {
		return Mount{}, false
	}
	readOnly := false
	for _, flag := range strings.Split(mode, ",") {
		if flag == "ro" {
			readOnly = true
		}
	}
	return Mount{
		HostPath:      host,
		ContainerPath: container,
		ReadOnly:      readOnly,
	}, true
}
