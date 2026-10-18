package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExitCodeContract(t *testing.T) {
	cases := []struct {
		name      string
		exposures []Exposure
		want      int
	}{
		{"clean config", nil, 0},
		{"empty slice", []Exposure{}, 0},
		{"one finding", []Exposure{{Path: "OPENROUTER_API_KEY", Gateway: "openrouter", Reachable: true}}, 1},
		{"finding not reachable still fails the gate", []Exposure{{Path: "K", Gateway: "openrouter", Reachable: false}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := New("test", SourceInfo{Path: "task.toml", Kind: "task_toml"}, NetworkInfo{Mode: "public"}, tc.exposures)
			if got := ExitCode(rep); got != tc.want {
				t.Errorf("ExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSummaryCounts(t *testing.T) {
	rep := New("test", SourceInfo{}, NetworkInfo{Mode: "public"}, []Exposure{
		{Path: "A", Reachable: true},
		{Path: "B", Reachable: false},
		{Path: "C", Reachable: true},
	})
	if rep.Summary.Total != 3 || rep.Summary.Reachable != 2 {
		t.Errorf("Summary = %+v, want total=3 reachable=2", rep.Summary)
	}
}

// The no-value contract: a report built from real-looking findings must
// not carry the secret values anywhere in its serialized forms.
func TestReportsNeverCarryValues(t *testing.T) {
	secrets := []string{
		"sk-or-v1-supersecretvalue0123456789abcdef",
		"ms-11111111-2222-3333-4444-555555555555",
	}
	exposures := []Exposure{
		{Fingerprint: "sk-or-v1-…(len=40) sha256:deadbeefdeadbeef", Surface: SurfaceEnv, Path: "OPENROUTER_API_KEY", Gateway: "openrouter", Reachable: true,
			Evidence: []ProbeRecord{{Kind: EvidencePolicy, Detail: "network_mode public"}}},
		{Fingerprint: "ms-…(len=36) sha256:cafebabecafebabe", Surface: SurfaceEnv, Path: "MODELSCOPE_SDK_TOKEN", Gateway: "modelscope"},
	}

	rep := New("test", SourceInfo{Path: "task.toml", Kind: "task_toml"}, NetworkInfo{Mode: "public"}, exposures)

	blob, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	RenderText(&buf, rep)
	var md bytes.Buffer
	RenderMarkdown(&md, rep)

	for _, out := range []string{string(blob), buf.String(), md.String()} {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("output leaked a secret value:\n%s", out)
			}
		}
	}
}

func TestJSONShape(t *testing.T) {
	rep := New("0.1.0", SourceInfo{Path: "task.toml", Kind: "task_toml"}, NetworkInfo{Mode: "allowlist", AllowedHosts: []string{"openrouter.ai"}},
		[]Exposure{{Fingerprint: "fp", Surface: SurfaceEnv, Path: "OPENROUTER_API_KEY", Gateway: "openrouter", Reachable: true, Resolved: true, Source: "value_shape"}})
	blob, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, blob)
	}
	for _, key := range []string{"tool", "version", "generated_at", "source", "network", "summary", "findings"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("JSON missing key %q:\n%s", key, blob)
		}
	}
	if rep.Findings == nil {
		t.Error("Findings should be an empty slice, not nil, so JSON renders []")
	}
}

func TestRenderTextAndMarkdownIncludeNamesNotValues(t *testing.T) {
	rep := New("0.1.0", SourceInfo{Path: "task.toml", Kind: "task_toml"}, NetworkInfo{Mode: "public"},
		[]Exposure{{Fingerprint: "sk-or-v1-…(len=40) sha256:deadbeef", Surface: SurfaceEnv, Path: "OPENROUTER_API_KEY", Gateway: "openrouter", Reachable: true, Resolved: true, Source: "value_shape",
			Evidence: []ProbeRecord{{Kind: EvidencePolicy, Detail: "network_mode \"public\": no egress control"}}}})

	var buf bytes.Buffer
	RenderText(&buf, rep)
	text := buf.String()
	for _, want := range []string{"OPENROUTER_API_KEY", "openrouter", "sha256:deadbeef", "benchgate gate task.toml"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "sk-or-v1-real") {
		t.Error("text output contains a value-like string")
	}

	var md bytes.Buffer
	RenderMarkdown(&md, rep)
	if !strings.Contains(md.String(), "| 1 | env | `OPENROUTER_API_KEY` | openrouter | true |") {
		t.Errorf("markdown table row missing:\n%s", md.String())
	}
}
