**English** | [简体中文](./README.md)

<div align="center">

# BenchGate

**Audit Agent eval sandboxes before the bench, swap model-reachable credentials for a mock gateway**

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=20&pause=1200&color=58A6FF&center=true&vCenter=true&multiline=true&width=760&height=70&lines=Audit%20the%20sandbox%20before%20the%20bench.%3BReal%20keys%20out%2C%20mock%20gateway%20in%2C%20exit%20code%20as%20the%20gate." alt="Audit the sandbox before the bench. Real keys out, mock gateway in, exit code as the gate." />

[![ci](https://img.shields.io/github/actions/workflow/status/SuperMarioYL/benchgate/ci.yml?branch=main&label=ci&logo=github)](https://github.com/SuperMarioYL/benchgate/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/SuperMarioYL/benchgate?logo=github)](https://github.com/SuperMarioYL/benchgate/releases)
[![Go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)](https://github.com/SuperMarioYL/benchgate/releases)
[![license](https://img.shields.io/github/license/SuperMarioYL/benchgate)](./LICENSE)

Coding-agent eval sandboxes like Harbor/Pier allow egress by default (`no-network`/`allowlist` isolation is opt-in), yet the bench config has to carry an OpenRouter or ModelScope gateway endpoint and key. Injected through `[environment.env]`, that key sits within reach of the model under test — and in the only publicly documented case so far, DeepSeek V4.1 Flash found and abused it. BenchGate produces a **credential exposure ledger** before the eval starts (`audit`) and turns "fix the config once" into a **repeatable CI gate** that swaps real credentials for a structurally identical local mock (`gate`).

[Quickstart](#quickstart) · [Demo](#demo) · [Capabilities and limits](#capabilities-and-limits) · [How it differs](#how-it-differs) · [Configuration](#configuration) · [Roadmap](#roadmap) · [Pricing](#pricing)

</div>

## Why a pre-bench credential gate

Three facts stack up to make a pre-bench credential audit a necessary step:

1. **The sandbox is not isolated by default, and the credentials are there by design.** Harbor's `network_mode` defaults to `public` (`no-network`/`allowlist` are opt-in); Pier's `allow_internet` defaults to `true`. At the same time, an eval must reach its inference gateway, so the OpenRouter/ModelScope endpoint and key usually live in `[environment.env]` and get resolved into the agent process environment at runtime. Together: by default, the model under test can get a real, spendable key.
2. **Models do find it.** A PSA on r/LocalLLaMA, which we then verified ourselves (line-by-line against the upstream sources of `harbor-framework/harbor` and `datacurve-ai/pier`, see [docs/evidence/repro.md](docs/evidence/repro.md)), reports that DeepSeek V4.1 Flash actively discovered and abused these reachable credentials inside Harbor/Pier sandboxes; the sibling models V4, GLM 5.3+Flash and Qwen were not observed doing so. Which behavior any given run will hit is unpredictable — exactly the part you don't want to guarantee by hand.
3. **Post-hoc tools can't unspoil a score.** gitleaks-style scanners look at repository code; by the time an OpenRouter spend alert fires, the tokens are burned and the run is wasted. What's missing is a gate that runs before the eval starts, is repeatable, and speaks in exit codes.

Running evals offline is not an answer: SWE-bench-style evals must reach the inference gateway. The right move is to keep gateway reachability and replace the real credentials — that's what `gate` does.

## Quickstart

### Install

```bash
# From source (Go 1.24+)
go install github.com/SuperMarioYL/benchgate/cmd/benchgate@v0.1.0

# Or grab a release binary (linux/darwin × amd64/arm64, with checksums.txt)
# https://github.com/SuperMarioYL/benchgate/releases
```

Single binary, no daemon. `audit` needs no Docker; its only outbound traffic is one unauthenticated GET against the gateway's `/models` endpoint (disable with `--offline`).

### A 60-second tour

The repo ships two example configs: `benchgate.example.yaml` (fixture keys with valid shapes, not live credentials) and its cleaned sibling `examples/clean.yaml`.

```bash
$ benchgate audit benchgate.example.yaml
benchgate 0.1.0 — credential exposure ledger
config: benchgate.example.yaml (job_yaml)
network: public
findings: 2 (reachable: 2)

[1] MODELSCOPE_SDK_TOKEN
    surface=env  gateway=modelscope  reachable=true
    detected=value_shape  resolved=true
    fingerprint: ms-…(len=39) sha256:0b08e5ab4b6dcd18
      - policy: network_mode "public": no egress control is configured, so the gateway endpoint is reachable and the credential is spendable
      - http_no_auth: GET https://api-inference.modelscope.cn/v1/models -> HTTP 200 (no auth header sent; the audited key was not used)
[2] OPENROUTER_API_KEY
    surface=env  gateway=openrouter  reachable=true
    detected=value_shape  resolved=true
    fingerprint: sk-or-v1-…(len=73) sha256:6f3fc1fd3a97c370
      - policy: network_mode "public": no egress control is configured, so the gateway endpoint is reachable and the credential is spendable
      - http_no_auth: GET https://openrouter.ai/api/v1/models -> HTTP 200 (no auth header sent; the audited key was not used)

remediation: remove the real keys from the sandbox config, or run
  benchgate gate benchgate.example.yaml -- <eval command>
to swap them for a local mock gateway before the eval starts.
$ echo $?
1
```

The exit code is the CI gate: any finding fails the step. The cleaned config:

```bash
$ benchgate audit examples/clean.yaml   # findings: 0, exit 0, eval may proceed
```

Wire it into the eval pipeline (ahead of the eval job):

```yaml
- name: pre-bench credential gate
  run: |
    go install github.com/SuperMarioYL/benchgate/cmd/benchgate@v0.1.0
    benchgate audit tasks/hello-world/task.toml
    # exit 1 → this step fails, the eval job never starts
```

### Swap in the mock before the eval

```bash
# Dry run first: rewrite → re-verify → restore, without starting the eval
benchgate gate benchgate.example.yaml --dry-run

# The real gate: inject the mock, run the eval command, restore the config
benchgate gate benchgate.example.yaml -- harbor run --task tasks/hello-world
```

`gate` starts a local OpenAI-compatible mock gateway, replaces every real credential value with a placeholder key and every real gateway URL with the mock address, re-verifies that "no real credential shapes and no real gateway references remain", and only then runs the eval command — injecting `BENCHGATE_MOCK_URL` into its environment.

## Demo

A roughly 30-second recording of the full flow (asciinema v2, captured from real runs; script at [docs/demo/record.sh](docs/demo/record.sh)):

[docs/demo/benchgate-audit.cast](docs/demo/benchgate-audit.cast) — audit reports the reachable credentials with their evidence; gate injects the mock gateway and re-verifies zero real egress.

```bash
asciinema play docs/demo/benchgate-audit.cast
```

Final stretch of the recording (with the mock injected, the eval process calling chat/completions only ever reaches the local mock):

```text
$ benchgate gate benchgate.example.yaml -- bash -c 'curl -s -X POST $BENCHGATE_MOCK_URL/chat/completions -d "{\"model\":\"deepseek-v4.1-flash\"}"'
gate: mock gateway at http://127.0.0.1:59196/api/v1
  MODELSCOPE_SDK_TOKEN         credential_value -> mock key  (value_shape; ms-…(len=39) sha256:0b08e5ab4b6dcd18)
  OPENAI_BASE_URL              gateway_url -> http://127.0.0.1:59196/api/v1  (references gateway host openrouter.ai)
  OPENROUTER_API_KEY           credential_value -> mock key  (value_shape; sk-or-v1-…(len=73) sha256:6f3fc1fd3a97c370)
  PROVIDER_BASE_URL            gateway_url -> http://127.0.0.1:59196/api/v1  (references gateway host openrouter.ai)
gate: re-verified — no real credential shapes and no real gateway endpoints remain in the patched config
{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"[benchgate-mock] This response came from the local mock gateway; no real provider was called.","role":"assistant"}}],"id":"chatcmpl-benchgate-mock","model":"deepseek-v4.1-flash","object":"chat.completion","usage":{"completion_tokens":0,"prompt_tokens":0,"total_tokens":0}}
gate: eval exited with code 0; mock gateway served 1 request(s) during the eval
```

## How it works

Single `benchgate` binary, no daemon, four internal stages:

```text
benchgate (Go single binary)
├── config loader──parse task.toml / job config.yaml / compose; enumerate env, mounts, network policy
├── detectors ────credential shapes: OpenRouter sk-or-, ModelScope ms-, generic sk-/Bearer, credential names and mount files
├── probe ────────policy-based reachability + unauthenticated GET {gateway}/models (never carries a credential)
├── mock gateway──local OpenAI-compatible mock; gate injects, re-verifies, restores
└── report ───────redacted ledger (terminal / JSON / Markdown) + CI exit code
```

Every ledger entry carries metadata only: variable name, prefix class, length, and a SHA-256 fingerprint (first 16 hex characters). **Credential values are never printed or written** — reports can be archived and diffed while the secrets themselves never enter any log.

## Capabilities and limits

| Capability | v0.1 status |
| --- | --- |
| Harbor `task.toml` parsing (incl. `[agent]` phase override, legacy `allow_internet`) | Implemented |
| Harbor job-level `config.yaml` and docker-compose parsing (env union + bind mounts) | Implemented |
| Value-shape detection: OpenRouter (`sk-or-v1-`/`sk-or-`), ModelScope (`ms-` UUID), generic `sk-`/`Bearer` | Implemented |
| Name-based detection (`*_KEY`/`*_TOKEN`/`*SECRET` …) and mounted files (`.env`, `id_rsa`, `*.pem` …) | Implemented |
| Reachability by network policy (public / allowlist / no-network) | Implemented |
| Unauthenticated gateway endpoint liveness probe (`GET /models`, no credentials) | Implemented |
| Redacted ledger: terminal / `--json` / `--output report.md` | Implemented |
| CI exit-code gate | Implemented |
| Mock gateway (models / chat/completions / completions / key) + rewrite + re-verify + restore | Implemented |
| `docker exec` forensics inside a running container | Not implemented — the audit is config-level, see below |
| Mock injection reachable from a container network | Not implemented (roadmap v0.2), see below |
| Hosted report upload | Not implemented (see [Pricing](#pricing)) |

Two honest caveats worth reading before you rely on it:

- **The audit is a config-level assessment plus an unauthenticated reachability check — not in-container forensics.** Reachability comes from the network policy the config declares (`public` → reachable; `allowlist` → reachable iff `allowed_hosts` covers the gateway host, matched generously on purpose, over-reporting by design; `no-network` → not reachable). The probe is a single `GET {gateway}/models` with no `Authorization` header: it records whether the endpoint is alive and the status code — the audited key is never used, and a transport failure is logged as inconclusive without flipping the verdict. v0.1 does not `docker exec` into containers.
- **The mock binds to loopback by default and is not automatically reachable from a container.** What `gate` guarantees in v0.1 is at the config level: after re-verification, the patched config contains no real key and no real gateway URL, so an eval started from it can only be handed the mock address. When the eval process shares a host with the mock (a harness run directly on the host, or a container with host networking), loopback is enough. When the model runs in its own Docker container network, you additionally need the mock reachable from that network (`--listen 0.0.0.0:<port>` plus a base URL pointing at a host-gateway address) — v0.1 does not automate this step; automating it is planned for v0.2.

## How it differs

Not another secret scanner. Each tool here looks at a different thing:

| Tool | What it audits | When | Response |
| --- | --- | --- | --- |
| gitleaks / trufflehog | Secrets already committed in repository code | At commit / in CI | Alert, block the merge |
| OpenRouter spend alerts | Billing consumption | After the fact | Damage control: rotate the key |
| Harbor/Pier network isolation | Container egress | At runtime | Opt-in config — and evals must keep the gateway reachable |
| **BenchGate** | Model-reachable credentials in the eval sandbox config | **Before the bench** | **Swap for a mock gateway + exit-code gate** |

BenchGate audits the environment, not the model, and mitigates by replacement rather than detection. It does not cover container escapes, prompt injection or full network scanning, and it does not patch Harbor/Pier upstream — deliberately a bypass so it can cover Harbor, Pier and similar self-built harnesses neutrally.

## Configuration

### Supported config formats

| Input | How it's recognized | What's extracted |
| --- | --- | --- |
| Harbor `task.toml` | `.toml` extension | `[environment.env]` string pairs; network policy from the `[agent]` phase override, falling back to `[environment]`; legacy `allow_internet = false` means no-network |
| Harbor job-level `config.yaml` | `.yaml`/`.yml` without a `services` key | `environment.env` and `network_mode` |
| docker-compose | `.yaml`/`.yml` with a `services` key | Env union across services (the model container shares the compose network), bind mounts; if any service can leave the compose network, the whole sandbox is treated as public |

Parsing is tolerant: unmodeled tables and fields (`[task]`, `[metadata]`, `[verifier]`, …) are ignored as-is, so Pier and similarly-shaped self-built harness configs parse too.

### network_mode verdicts

| Policy | Reachability verdict |
| --- | --- |
| `public` (default; unset, `bridge`, `host` etc. all land here) | Gateway reachable, credential spendable |
| `allowlist` | Reachable only if `allowed_hosts` covers the gateway host (exact entries, subdomains and `*.suffix` wildcards; generous matching, over-reporting reachability) |
| `no-network` | Not reachable, credential not spendable |

### Commands and flags

```text
benchgate audit <task.toml|config.yaml|docker-compose.yaml>
  --json          print the report as JSON to stdout
  --output FILE   write the report to a file (.md renders Markdown, anything else JSON);
                  the terminal ledger is still printed
  --offline       skip the live gateway endpoint probe (air-gapped audit hosts)

benchgate gate <config> -- <eval command>
  --dry-run       rewrite, re-verify and restore without starting the eval
  --listen ADDR   address for the mock gateway (default 127.0.0.1:0)
```

Exit codes: `0` no findings; `1` findings or an error. The gate verdict is deliberately binary — per-finding `reachable` details live in the report for humans, while the exit code avoids policy-dependent interpretation so the gate can't drift.

Restore in `gate` is crash-safe: the original config is backed up as `*.benchgate.bak` before the eval starts. Beyond normal completion, SIGINT/SIGTERM forwarding and passing through the eval's own exit code, even a SIGKILLed gate process leaves the original config on disk.

## Roadmap

- **v0.1.x** — more provider credential shapes (generic `sk-`/`Bearer` already covers mainstream OpenAI-compatible gateways); report format improvements.
- **v0.2** — mock injection automatically reachable from container networks (host-gateway automation); `benchgate-action`: reuse the whole gate as a single CI step.
- **hosted** — `benchgate upload` report submission, team policy profiles and drift alerts (see [Pricing](#pricing)).
- **Upstream tracking** — if Harbor/Pier start stripping credentials by default or shipping an official mock (e.g. the direction of PR #3538), `audit` remains as a compliance verifier; the tracking log lives in [docs/evidence/repro.md](docs/evidence/repro.md).

## Pricing

**Hosted team policy tier** (planned; v0.1 ships no SaaS component and uploads no data): **$99/month/organization**, early-bird **$49/month** for the first 10 teams.

Built for CI teams that want "gate exit 0" written into their org's eval policy:

- Organization-wide gateway allowlist and enforced-gate policy profiles
- Eval-config drift alerts (re-audit on every harness/model bump)
- 90-day report retention
- Private mock image

The CLI and self-hosting are fully featured MIT-licensed software; the hosted tier gates nothing locally. For early access and requirements: open a [GitHub issue](https://github.com/SuperMarioYL/benchgate/issues).

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
