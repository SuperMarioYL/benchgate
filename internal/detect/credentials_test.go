package detect

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/SuperMarioYL/benchgate/internal/config"
)

// TestScanEnvValueShapes is the table of credential shapes and their
// expected gateway classification.
func TestScanEnvValueShapes(t *testing.T) {
	cases := []struct {
		name         string
		env          map[string]string
		wantFindings int
		want         map[string]struct {
			gateway string
			source  string
			resolve bool
		}
	}{
		{
			name:         "openrouter v1 key",
			env:          map[string]string{"OPENROUTER_API_KEY": "sk-or-v1-0123456789abcdef0123456789abcdef"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"OPENROUTER_API_KEY": {GatewayOpenRouter, SourceValueShape, true}},
		},
		{
			name:         "openrouter legacy prefix",
			env:          map[string]string{"OPENROUTER_API_KEY": "sk-or-abcdef123456"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"OPENROUTER_API_KEY": {GatewayOpenRouter, SourceValueShape, true}},
		},
		{
			name:         "modelscope uuid token",
			env:          map[string]string{"MODELSCOPE_SDK_TOKEN": "ms-01234567-89ab-cdef-0123-456789abcdef"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"MODELSCOPE_SDK_TOKEN": {GatewayModelScope, SourceValueShape, true}},
		},
		{
			name:         "generic sk- shape on a non-descript name",
			env:          map[string]string{"LLM_CREDENTIAL": "sk-abcdefghijklmnop1234"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"LLM_CREDENTIAL": {GatewayUnknown, SourceValueShape, true}},
		},
		{
			name:         "bearer header pasted as value",
			env:          map[string]string{"GATEWAY_AUTH": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"GATEWAY_AUTH": {GatewayUnknown, SourceValueShape, true}},
		},
		{
			name:         "name-only detection with plain value",
			env:          map[string]string{"ANTHROPIC_API_KEY": "some-opaque-value"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"ANTHROPIC_API_KEY": {GatewayUnknown, SourceVarName, true}},
		},
		{
			name:         "host template is unresolved but still a surface",
			env:          map[string]string{"OPENROUTER_API_KEY": "${OPENROUTER_API_KEY}"},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"OPENROUTER_API_KEY": {GatewayUnknown, SourceVarName, false}},
		},
		{
			name:         "compose host passthrough with no value",
			env:          map[string]string{"PASSTHROUGH_TOKEN": ""},
			wantFindings: 1,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{"PASSTHROUGH_TOKEN": {GatewayUnknown, SourceVarName, false}},
		},
		{
			name:         "benign values are not findings",
			env:          map[string]string{"MODEL_PORT": "8080", "DEBUG": "1", "HOME": "/root"},
			wantFindings: 0,
		},
		{
			name:         "url values are configuration, not secrets",
			env:          map[string]string{"API_KEY_URL": "https://keys.example.com", "OPENAI_BASE_URL": "https://openrouter.ai/api/v1"},
			wantFindings: 0,
		},
		{
			name:         "tokenizer paths are not credentials",
			env:          map[string]string{"TOKENIZER_PATH": "/usr/share/tokenizer", "MONKEY_PATCH": "1"},
			wantFindings: 0,
		},
		{
			name:         "case-insensitive names",
			env:          map[string]string{"my_api_key": "plain-value", "GitHub_Token": "ghp_value"},
			wantFindings: 2,
			want: map[string]struct {
				gateway string
				source  string
				resolve bool
			}{
				"my_api_key":   {GatewayUnknown, SourceVarName, true},
				"GitHub_Token": {GatewayUnknown, SourceVarName, true},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanEnv(tc.env)
			if len(got) != tc.wantFindings {
				t.Fatalf("ScanEnv found %d findings (%v), want %d", len(got), got, tc.wantFindings)
			}
			for _, ex := range got {
				want, ok := tc.want[ex.Path]
				if !ok {
					t.Errorf("unexpected finding for %q", ex.Path)
					continue
				}
				if ex.Gateway != want.gateway {
					t.Errorf("%s: Gateway = %q, want %q", ex.Path, ex.Gateway, want.gateway)
				}
				if ex.Source != want.source {
					t.Errorf("%s: Source = %q, want %q", ex.Path, ex.Source, want.source)
				}
				if ex.Resolved != want.resolve {
					t.Errorf("%s: Resolved = %t, want %t", ex.Path, ex.Resolved, want.resolve)
				}
				if ex.Surface != "env" {
					t.Errorf("%s: Surface = %q, want env", ex.Path, ex.Surface)
				}
			}
		})
	}
}

// ScanEnv output must be deterministic (sorted by variable name) so
// reports diff cleanly between runs.
func TestScanEnvSortedByName(t *testing.T) {
	env := map[string]string{
		"ZZ_TOKEN":           "value-zz",
		"OPENROUTER_API_KEY": "sk-or-v1-0123456789abcdef0123456789abcdef",
		"AA_SECRET":          "value-aa",
	}
	got := ScanEnv(env)
	var names []string
	for _, ex := range got {
		names = append(names, ex.Path)
	}
	want := []string{"AA_SECRET", "OPENROUTER_API_KEY", "ZZ_TOKEN"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("order = %v, want %v", names, want)
	}
}

// The hard product contract: detection output must never contain the
// values it scanned.
func TestScanEnvNeverEmitsValues(t *testing.T) {
	secrets := []string{
		"sk-or-v1-live-key-do-not-leak-0123456789abcdef",
		"ms-11111111-2222-3333-4444-555555555555",
		"plain-opaque-secret-value",
	}
	env := map[string]string{
		"OPENROUTER_API_KEY":   secrets[0],
		"MODELSCOPE_SDK_TOKEN": secrets[1],
		"ANTHROPIC_API_KEY":    secrets[2],
	}
	got := ScanEnv(env)
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(blob), s) {
			t.Errorf("detection output leaked a secret value:\n%s", blob)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a := Fingerprint("sk-or-v1-", "sk-or-v1-0123456789abcdef")
	b := Fingerprint("sk-or-v1-", "sk-or-v1-0123456789abcdef")
	c := Fingerprint("sk-or-v1-", "sk-or-v1-fedcba9876543210")

	if a != b {
		t.Error("fingerprint must be stable for the same value")
	}
	if a == c {
		t.Error("different values must produce different fingerprints")
	}
	if !strings.Contains(a, "sha256:") || !strings.Contains(a, "(len=") {
		t.Errorf("fingerprint = %q, want prefix class, length and sha256 parts", a)
	}
	if strings.Contains(a, "0123456789abcdef") {
		t.Errorf("fingerprint must not embed the value: %q", a)
	}
	if got := Fingerprint("", ""); !strings.Contains(got, "unresolved") {
		t.Errorf("Fingerprint(\"\") = %q, want unresolved marker", got)
	}
}

func TestScanMounts(t *testing.T) {
	mounts := []struct {
		path string
		want bool
	}{
		{"/home/user/project/.env", true},
		{"/home/user/project/.env.production", true},
		{"/home/user/.netrc", true},
		{"/srv/credentials.json", true},
		{"/etc/certs/server.pem", true},
		{"/etc/certs/server.key", true},
		{"/home/user/.ssh/id_rsa", true},
		{"/workspace/task-data", false},
		{"/workspace/tokenizer", false},
		{"/workspace/config.yaml", false},
	}
	for _, tc := range mounts {
		got := ScanMounts([]config.Mount{{HostPath: tc.path, ContainerPath: "/mnt/data"}})
		if tc.want && len(got) != 1 {
			t.Errorf("%s: want 1 finding, got %d", tc.path, len(got))
		}
		if !tc.want && len(got) != 0 {
			t.Errorf("%s: want no finding, got %v", tc.path, got)
		}
		if tc.want && len(got) == 1 {
			if got[0].Surface != "mounted_file" || got[0].Source != SourceMountName {
				t.Errorf("%s: surface/source = %q/%q", tc.path, got[0].Surface, got[0].Source)
			}
			if got[0].Path != tc.path {
				t.Errorf("%s: Path = %q", tc.path, got[0].Path)
			}
		}
	}
}

func TestGatewayMappings(t *testing.T) {
	if GatewayHost(GatewayOpenRouter) != "openrouter.ai" {
		t.Error("openrouter host")
	}
	if GatewayHost(GatewayModelScope) != "api-inference.modelscope.cn" {
		t.Error("modelscope host")
	}
	if GatewayBaseURL(GatewayOpenRouter) != OpenRouterBaseURL || GatewayBaseURL(GatewayModelScope) != ModelScopeBaseURL {
		t.Error("base urls")
	}
	cases := map[string]string{
		"https://openrouter.ai/api/v1":                  GatewayOpenRouter,
		"https://api.openrouter.ai/api/v1":              GatewayOpenRouter,
		"${OPENROUTER_BASE_URL:-https://openrouter.ai}": GatewayOpenRouter,
		"https://api-inference.modelscope.cn/v1":        GatewayModelScope,
		"http://localhost:8080/v1":                      GatewayUnknown,
	}
	for value, want := range cases {
		if got := GatewayForHost(value); got != want {
			t.Errorf("GatewayForHost(%q) = %q, want %q", value, got, want)
		}
	}
}
