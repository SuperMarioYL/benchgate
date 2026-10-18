package probe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SuperMarioYL/benchgate/internal/config"
	"github.com/SuperMarioYL/benchgate/internal/detect"
	"github.com/SuperMarioYL/benchgate/internal/report"
)

// offline prober: no outbound HTTP in unit tests.
func testProber() *Prober {
	return NewProber(true, 250*time.Millisecond)
}

// TestAssessNetworkModes is the policy table across the three network
// modes the config loader normalizes to.
func TestAssessNetworkModes(t *testing.T) {
	cases := []struct {
		name         string
		networkMode  string
		allowedHosts []string
		gateway      string
		want         bool
	}{
		{"public allows egress", config.NetworkPublic, nil, detect.GatewayOpenRouter, true},
		{"no-network blocks", config.NetworkNone, nil, detect.GatewayOpenRouter, false},
		{"allowlist exact entry", config.NetworkAllowlist, []string{"openrouter.ai"}, detect.GatewayOpenRouter, true},
		{"allowlist wildcard subdomain", config.NetworkAllowlist, []string{"*.modelscope.cn"}, detect.GatewayModelScope, true},
		{"allowlist subdomain of exact entry", config.NetworkAllowlist, []string{"modelscope.cn"}, detect.GatewayModelScope, true},
		{"allowlist miss", config.NetworkAllowlist, []string{"*.modelscope.cn"}, detect.GatewayOpenRouter, false},
		{"allowlist empty blocks", config.NetworkAllowlist, nil, detect.GatewayOpenRouter, false},
		{"unknown gateway under public", config.NetworkPublic, nil, detect.GatewayUnknown, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.SandboxConfig{NetworkMode: tc.networkMode, AllowedHosts: tc.allowedHosts}
			exposures := []report.Exposure{{Surface: report.SurfaceEnv, Path: "OPENROUTER_API_KEY", Gateway: tc.gateway}}

			got := testProber().Assess(cfg, exposures)
			if len(got) != 1 {
				t.Fatalf("Assess returned %d exposures, want 1", len(got))
			}
			if got[0].Reachable != tc.want {
				t.Errorf("Reachable = %t, want %t", got[0].Reachable, tc.want)
			}
			if len(got[0].Evidence) == 0 {
				t.Error("policy evidence missing")
			}
			if got[0].Evidence[0].Kind != report.EvidencePolicy {
				t.Errorf("first evidence kind = %q, want policy", got[0].Evidence[0].Kind)
			}
			if got[0].Evidence[0].Detail == "" {
				t.Error("policy evidence detail is empty")
			}
		})
	}
}

// Assess must not mutate its input slice.
func TestAssessDoesNotMutateInput(t *testing.T) {
	cfg := &config.SandboxConfig{NetworkMode: config.NetworkNone}
	exposures := []report.Exposure{{Surface: report.SurfaceEnv, Path: "K", Gateway: detect.GatewayOpenRouter}}
	testProber().Assess(cfg, exposures)
	if exposures[0].Reachable {
		t.Error("input exposure was mutated")
	}
	if len(exposures[0].Evidence) != 0 {
		t.Error("input exposure evidence was mutated")
	}
}

func TestAssessMountedFile(t *testing.T) {
	cfg := &config.SandboxConfig{NetworkMode: config.NetworkNone} // even no-network: the bytes are in the container
	exposures := []report.Exposure{{Surface: report.SurfaceMountedFile, Path: "/home/u/.env", Gateway: detect.GatewayUnknown}}
	got := testProber().Assess(cfg, exposures)
	if !got[0].Reachable {
		t.Error("mounted secret file should be reachable (bytes readable in container)")
	}
	if got[0].Evidence[0].Kind != report.EvidenceMount {
		t.Errorf("evidence kind = %q, want mount", got[0].Evidence[0].Kind)
	}
}

// The live check must never attach credentials to its request.
func TestProbeEndpointSendsNoAuth(t *testing.T) {
	var sawAuth, sawBenchgateUA bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		sawBenchgateUA = strings.HasPrefix(r.Header.Get("User-Agent"), "benchgate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	p := NewProber(false, time.Second)
	rec := p.ProbeEndpoint(srv.URL + "/api/v1/models")

	if sawAuth {
		t.Error("probe request carried an Authorization header")
	}
	if !sawBenchgateUA {
		t.Error("probe request missing benchgate user agent")
	}
	if rec.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", rec.StatusCode)
	}
	if rec.DurationMS < 0 {
		t.Errorf("DurationMS = %d", rec.DurationMS)
	}
	if !strings.Contains(rec.Detail, "no auth header sent") {
		t.Errorf("Detail = %q", rec.Detail)
	}
	if rec.Kind != report.EvidenceHTTPProbe {
		t.Errorf("Kind = %q, want %q", rec.Kind, report.EvidenceHTTPProbe)
	}
}

func TestProbeEndpointTransportFailureIsInconclusive(t *testing.T) {
	// Reserve a port and close the listener: nothing is listening.
	p := NewProber(false, 500*time.Millisecond)
	rec := p.ProbeEndpoint("http://127.0.0.1:1/api/v1/models")
	if rec.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0 for failed probe", rec.StatusCode)
	}
	if !strings.Contains(rec.Detail, "inconclusive") {
		t.Errorf("Detail = %q, want inconclusive marker", rec.Detail)
	}
}

func TestHostAllowed(t *testing.T) {
	cases := []struct {
		allowed []string
		host    string
		want    bool
	}{
		{[]string{"openrouter.ai"}, "openrouter.ai", true},
		{[]string{"openrouter.ai"}, "api.openrouter.ai", true},   // subdomain of exact entry
		{[]string{"openrouter.ai"}, "notopenrouter.ai", false},   // suffix without dot boundary
		{[]string{"*.modelscope.cn"}, "a.b.modelscope.cn", true}, // wildcard subdomains
		{[]string{"*.modelscope.cn"}, "modelscope.cn", false},    // wildcard does not match the apex
		{[]string{"*.modelscope.cn"}, "openrouter.ai", false},
		{[]string{" modelscope.cn "}, "modelscope.cn", true}, // whitespace trimmed
		{nil, "openrouter.ai", false},
		{[]string{"openrouter.ai"}, "", false},
	}
	for _, tc := range cases {
		_, got := HostAllowed(tc.allowed, tc.host)
		if got != tc.want {
			t.Errorf("HostAllowed(%v, %q) = %t, want %t", tc.allowed, tc.host, got, tc.want)
		}
	}
}

// The live endpoint check runs once per gateway and is shared across
// exposures of that gateway.
func TestAssessSharesLiveCheckPerGateway(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewProber(false, time.Second)
	p.endpoints = map[string]string{detect.GatewayOpenRouter: srv.URL}

	cfg := &config.SandboxConfig{NetworkMode: config.NetworkPublic}
	exposures := []report.Exposure{
		{Surface: report.SurfaceEnv, Path: "A", Gateway: detect.GatewayOpenRouter},
		{Surface: report.SurfaceEnv, Path: "B", Gateway: detect.GatewayOpenRouter},
	}
	got := p.Assess(cfg, exposures)
	if len(got) != 2 || !got[0].Reachable || !got[1].Reachable {
		t.Fatalf("unexpected result: %+v", got)
	}
	for _, ex := range got {
		if len(ex.Evidence) != 2 { // policy + shared live check
			t.Errorf("%s: evidence = %+v, want policy + one shared live check", ex.Path, ex.Evidence)
		}
	}
	if hits != 1 {
		t.Errorf("live endpoint hit %d times, want 1 (cached per gateway)", hits)
	}
}
