// Package detect identifies credential shapes on the surfaces a sandbox
// config exposes to the model under test: injected env vars and host
// files bind-mounted into the container.
//
// Detection runs on values but never returns them. Every finding carries
// metadata only — variable name, prefix class, length and a SHA-256
// fingerprint — so downstream code (reports, logs, rewrites) is
// structurally unable to print or persist a secret.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/SuperMarioYL/benchgate/internal/config"
	"github.com/SuperMarioYL/benchgate/internal/report"
)

// Gateways BenchGate knows the endpoints for.
const (
	GatewayOpenRouter = "openrouter"
	GatewayModelScope = "modelscope"
	GatewayUnknown    = "unknown"
)

// How a credential was detected.
const (
	SourceValueShape = "value_shape"
	SourceVarName    = "var_name"
	SourceMountName  = "mount_name"
)

// Real gateway endpoints a detected key would be spent at.
const (
	OpenRouterBaseURL = "https://openrouter.ai/api/v1"
	ModelScopeBaseURL = "https://api-inference.modelscope.cn/v1"
)

// GatewayHost maps a gateway to the endpoint host its clients call.
func GatewayHost(gateway string) string {
	switch gateway {
	case GatewayOpenRouter:
		return "openrouter.ai"
	case GatewayModelScope:
		return "api-inference.modelscope.cn"
	default:
		return ""
	}
}

// GatewayBaseURL maps a gateway to its API base URL.
func GatewayBaseURL(gateway string) string {
	switch gateway {
	case GatewayOpenRouter:
		return OpenRouterBaseURL
	case GatewayModelScope:
		return ModelScopeBaseURL
	default:
		return ""
	}
}

// GatewayForHost reverse-looks-up which known gateway an env value
// references (by substring match on the host, covering subdomains).
// Returns GatewayUnknown when none matches.
func GatewayForHost(value string) string {
	v := strings.ToLower(value)
	switch {
	case strings.Contains(v, "openrouter.ai"):
		return GatewayOpenRouter
	case strings.Contains(v, "modelscope.cn"):
		return GatewayModelScope
	default:
		return GatewayUnknown
	}
}

// openrouterPrefix covers sk-or-v1-... and the legacy sk-or-... shape.
const openrouterPrefix = "sk-or-"

// modelscopeTokenRe is the ms-UUID shape ModelScope issues as SDK token.
var modelscopeTokenRe = regexp.MustCompile(`^ms-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// bearerRe matches an Authorization header value pasted as an env value.
var bearerRe = regexp.MustCompile(`(?i)^bearer\s+\S{4,}$`)

// credentialNameRe matches variable names that are credentials by
// convention. Boundaries keep benign names like TOKENIZER_PATH or
// MONKEY_PATCH out.
var credentialNameRe = regexp.MustCompile(`(?i)(api[_-]?key|apikey|_key$|^key$|_token$|^token$|_token_|secret|password|passwd|private[_-]?key|credential)`)

// mountBaseNames are file names that are credentials by convention.
var mountBaseNames = map[string]bool{
	".env": true, ".netrc": true, ".npmrc": true, ".git-credentials": true,
	"credentials": true, "credentials.json": true,
	"id_rsa": true, "id_ed25519": true, "id_ecdsa": true,
}

// mountSuffixes are file extensions that carry key material.
var mountSuffixes = []string{".pem", ".key", ".p12", ".pfx"}

// ScanEnv classifies every env var in the map and returns the findings
// sorted by variable name for deterministic output.
func ScanEnv(env map[string]string) []report.Exposure {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)

	exposures := make([]report.Exposure, 0, len(names))
	for _, name := range names {
		if ex, ok := classifyEnvVar(name, env[name]); ok {
			exposures = append(exposures, ex)
		}
	}
	return exposures
}

// classifyEnvVar decides whether one env var is a credential surface.
// Value shapes win over name shapes; URL values are never credentials.
func classifyEnvVar(name, value string) (report.Exposure, bool) {
	v := strings.TrimSpace(value)

	gateway, prefixClass := matchValueShape(v)
	if gateway != "" {
		return report.Exposure{
			Fingerprint: Fingerprint(prefixClass, v),
			Surface:     report.SurfaceEnv,
			Path:        name,
			Gateway:     gateway,
			Resolved:    true,
			Source:      SourceValueShape,
		}, true
	}

	// Name-based fallback. A value that is a URL is configuration (a
	// base URL), not a secret; host-side templates and passthroughs are
	// still surfaces because the harness resolves them at runtime.
	if credentialNameRe.MatchString(name) &&
		!strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		resolved := v != "" && !strings.Contains(v, "${")
		fp := ""
		if resolved {
			fp = Fingerprint("", v)
		} else {
			fp = "unresolved (value is resolved from the host at runtime)"
		}
		return report.Exposure{
			Fingerprint: fp,
			Surface:     report.SurfaceEnv,
			Path:        name,
			Gateway:     GatewayUnknown,
			Resolved:    resolved,
			Source:      SourceVarName,
		}, true
	}

	return report.Exposure{}, false
}

// matchValueShape returns the owning gateway and prefix class for
// credential-shaped values, or empty strings when the value is not a
// recognizable secret shape.
func matchValueShape(v string) (gateway, prefixClass string) {
	switch {
	case strings.HasPrefix(v, openrouterPrefix) && len(v) >= 14:
		// Report the actual prefix: sk-or-v1- for current keys, sk-or-
		// for the legacy shape.
		if strings.HasPrefix(v, "sk-or-v1-") {
			return GatewayOpenRouter, "sk-or-v1-"
		}
		return GatewayOpenRouter, "sk-or-"
	case modelscopeTokenRe.MatchString(v):
		return GatewayModelScope, "ms-"
	case strings.HasPrefix(v, "sk-") && len(v) >= 16:
		return GatewayUnknown, "sk-"
	case bearerRe.MatchString(v):
		return GatewayUnknown, "bearer"
	default:
		return "", ""
	}
}

// ScanMounts flags bind mounts whose host file name is a credential by
// convention. The file content is never read.
func ScanMounts(mounts []config.Mount) []report.Exposure {
	exposures := make([]report.Exposure, 0, len(mounts))
	for _, m := range mounts {
		base := strings.ToLower(m.HostPath)
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}
		flagged := mountBaseNames[base] ||
			strings.HasPrefix(base, ".env") ||
			strings.Contains(base, "credential")
		if !flagged {
			for _, suffix := range mountSuffixes {
				if strings.HasSuffix(base, suffix) {
					flagged = true
					break
				}
			}
		}
		if !flagged {
			continue
		}
		exposures = append(exposures, report.Exposure{
			Fingerprint: Fingerprint("path", m.HostPath),
			Surface:     report.SurfaceMountedFile,
			Path:        m.HostPath,
			Gateway:     GatewayUnknown,
			Resolved:    true,
			Source:      SourceMountName,
		})
	}
	return exposures
}

// Fingerprint builds the redacted identifier for a value: prefix class,
// length and the first 16 hex chars of the SHA-256. It is stable across
// runs, so ledgers can be diffed, and it carries no recoverable value.
func Fingerprint(prefixClass, value string) string {
	if value == "" {
		return "unresolved (no value in config)"
	}
	sum := sha256.Sum256([]byte(value))
	if prefixClass == "" {
		prefixClass = "secret"
	}
	return fmt.Sprintf("%s…(len=%d) sha256:%s", prefixClass, len(value), hex.EncodeToString(sum[:8]))
}
