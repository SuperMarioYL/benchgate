// Package probe verifies, from the sandbox's perspective, whether a
// detected credential's gateway endpoint is reachable under the config's
// network policy.
//
// The audit is config-level: it reasons about the policy the harness
// will apply when the eval starts (public egress by default, allowlist,
// or no-network), and optionally live-checks the gateway endpoint from
// the audit host with a plain unauthenticated HTTP GET. The probe never
// sends a credential — an authenticated call against a real provider
// with a real key would be the exact leak BenchGate exists to prevent.
package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SuperMarioYL/benchgate/internal/config"
	"github.com/SuperMarioYL/benchgate/internal/detect"
	"github.com/SuperMarioYL/benchgate/internal/report"
)

// DefaultTimeout bounds the live endpoint check.
const DefaultTimeout = 4 * time.Second

// Prober assesses reachability. The zero value is usable but callers
// should prefer NewProber.
type Prober struct {
	// Offline skips the live endpoint check (air-gapped audit hosts).
	Offline bool
	// Timeout bounds each live endpoint check.
	Timeout time.Duration
	// endpoints overrides gateway base URLs (tests point them at a
	// local server); nil means the real provider endpoints.
	endpoints map[string]string
	client    *http.Client
}

// NewProber returns a prober with the given behavior.
func NewProber(offline bool, timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Prober{
		Offline: offline,
		Timeout: timeout,
		client:  &http.Client{Timeout: timeout},
	}
}

// Assess fills Reachable and Evidence on every exposure. Inputs are not
// mutated; a copy is returned. The live endpoint check runs once per
// known gateway and is reused across exposures.
func (p *Prober) Assess(cfg *config.SandboxConfig, exposures []report.Exposure) []report.Exposure {
	out := make([]report.Exposure, len(exposures))
	copy(out, exposures)

	live := map[string]report.ProbeRecord{}
	for i := range out {
		ex := &out[i]

		if ex.Surface == report.SurfaceMountedFile {
			// A bind-mounted secret file is readable by the model under
			// test by construction; network policy does not change that.
			ex.Reachable = true
			ex.Evidence = append(ex.Evidence, report.ProbeRecord{
				Kind:   report.EvidenceMount,
				Detail: fmt.Sprintf("host path %q is bind-mounted into the sandbox; its bytes are readable by the model under test", ex.Path),
			})
			continue
		}

		reachable, evidence := assessPolicy(cfg, ex.Gateway)
		ex.Reachable = reachable
		ex.Evidence = append(ex.Evidence, evidence)

		if reachable && !p.Offline && ex.Gateway != detect.GatewayUnknown {
			rec, ok := live[ex.Gateway]
			if !ok {
				rec = p.LiveCheck(ex.Gateway)
				live[ex.Gateway] = rec
			}
			ex.Evidence = append(ex.Evidence, rec)
		}
	}
	return out
}

// assessPolicy applies the config's network policy to one gateway.
func assessPolicy(cfg *config.SandboxConfig, gateway string) (bool, report.ProbeRecord) {
	host := detect.GatewayHost(gateway)

	switch cfg.NetworkMode {
	case config.NetworkNone:
		return false, report.ProbeRecord{
			Kind:   report.EvidencePolicy,
			Detail: fmt.Sprintf("network_mode %q blocks all container egress; the gateway endpoint is not reachable and the credential is not spendable", cfg.NetworkMode),
		}
	case config.NetworkAllowlist:
		entry, ok := HostAllowed(cfg.AllowedHosts, host)
		if ok {
			return true, report.ProbeRecord{
				Kind:   report.EvidencePolicy,
				Detail: fmt.Sprintf("network_mode %q: allowed_hosts entry %q covers %q, so the gateway endpoint is reachable and the credential is spendable", cfg.NetworkMode, entry, host),
			}
		}
		return false, report.ProbeRecord{
			Kind:   report.EvidencePolicy,
			Detail: fmt.Sprintf("network_mode %q: no allowed_hosts entry covers %q, so the gateway endpoint is not reachable", cfg.NetworkMode, host),
		}
	default:
		// Public (or an unknown mode the loader already normalized to
		// public): no egress control, the key is spendable.
		return true, report.ProbeRecord{
			Kind:   report.EvidencePolicy,
			Detail: fmt.Sprintf("network_mode %q: no egress control is configured, so the gateway endpoint is reachable and the credential is spendable", cfg.NetworkMode),
		}
	}
}

// HostAllowed reports whether host is covered by an allowlist entry.
// Matching is deliberately generous (exact entry, subdomains of the
// entry, and *.suffix wildcards): for a security audit, overstating
// reachability fails closed, understating it hides an exposure.
// Returns the matching entry for evidence.
func HostAllowed(allowed []string, host string) (string, bool) {
	if host == "" {
		return "", false
	}
	for _, entry := range allowed {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		switch {
		case e == host:
			return entry, true
		case strings.HasPrefix(e, "*.") && strings.HasSuffix(host, e[1:]):
			// *.suffix matches subdomains of suffix, not suffix itself.
			if host != e[1:] {
				return entry, true
			}
		case strings.HasSuffix(host, "."+e):
			return entry, true
		}
	}
	return "", false
}

// LiveCheck probes the gateway's public models list with a plain GET and
// no Authorization header, recording status and latency as evidence. A
// transport failure is recorded as inconclusive — it never changes a
// Reachable verdict, which is policy-based by contract.
func (p *Prober) LiveCheck(gateway string) report.ProbeRecord {
	base := detect.GatewayBaseURL(gateway)
	if override, ok := p.endpoints[gateway]; ok {
		base = override
	}
	return p.ProbeEndpoint(base + "/models")
}

// ProbeEndpoint performs the unauthenticated reachability check against
// one URL. No credential is ever attached to the request.
func (p *Prober) ProbeEndpoint(endpoint string) report.ProbeRecord {
	rec := report.ProbeRecord{Kind: report.EvidenceHTTPProbe}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		rec.Detail = fmt.Sprintf("GET %s could not be built: %v", endpoint, err)
		return rec
	}
	// Deliberately no Authorization header: this probe must never carry
	// a credential, its own or the audited one.
	req.Header.Set("User-Agent", "benchgate-probe")

	start := time.Now()
	resp, err := p.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		rec.Detail = fmt.Sprintf("GET %s failed after %s (%v); endpoint liveness inconclusive", endpoint, duration.Round(time.Millisecond), err)
		return rec
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	rec.StatusCode = resp.StatusCode
	rec.DurationMS = duration.Milliseconds()
	rec.Detail = fmt.Sprintf("GET %s -> HTTP %d (no auth header sent; the audited key was not used)", endpoint, resp.StatusCode)
	return rec
}
