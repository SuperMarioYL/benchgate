# Changelog

All notable changes to BenchGate are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.2.0] - 2026-11-22

Fix-led iteration on v0.1.0: three fail-open defects closed, plus the promised
container-reachable mock injection.

### Fixed

- `audit` attributes a name-only credential (`OPENROUTER_API_KEY = "${...}"`) to its
  gateway (`openrouter`/`modelscope` from the variable name) and, under `allowlist`,
  treats an unattributable gateway as reachable (fail closed) instead of matching an
  empty host and printing `covers ""`.
- docker-compose `env_file` entries are read into the env union and audited; a declared
  but unreadable env_file is a hard error instead of a silent skip that exited 0.
- Bind mounts whose host source is host-interpolated (`${HOME}/.aws/credentials`) are kept
  as surfaces instead of being dropped by the volume parser.
- `gate` refuses before starting the mock or the eval when a credential lives in a
  bind-mounted file or an `env_file`; it previously warned, declared "no credential
  findings", ran the eval and exited 0 with the real credentials still readable.

### Added

- `gate --container-reachable`: binds the mock on all interfaces and writes a base URL
  containers can reach (`host.docker.internal` on Docker Desktop, first non-loopback IPv4
  on Linux); a loopback-only `--listen` is rejected. This ships the v0.2 roadmap item; the
  `benchgate-action` promise is re-scoped to v0.3.
- Regression tests for every fix above, verified failing against the v0.1.0 tag.

### Changed

- README.md / README.en.md capability tables, caveats, command reference and roadmap now
  describe the shipped behavior; the site content baseline is refreshed to v0.2.0.

## [0.1.0] - 2026-10-18

First release: pre-bench credential audit and mock-gateway gate for Harbor/Pier eval sandboxes.

### m1 — evidence: verify the exposure

- `docs/evidence/repro.md`: the three INVESTIGATE checks, recorded with citations —
  upstream source verification that Harbor (`harbor-framework/harbor` @ `c3cc0d2e`) and
  Pier (`datacurve-ai/pier` @ `4d3c1404`) still inject `[environment.env]` credentials
  into the agent process with public egress by default; retrieval and cross-check of the
  r/LocalLLaMA PSA; operator-demand signals (interviews not conducted — recorded as a
  partial pass with public substitutes).

### m2 — audit: the exposure ledger and CI exit code

- Config loader for the surfaces a sandbox exposes: Harbor `task.toml` (with `[agent]`
  phase override and legacy `allow_internet`), job-level `config.yaml`, and
  docker-compose (env union across services, bind mounts, egress-conservative policy).
- Credential detectors that return metadata only (name, prefix class, length, SHA-256
  fingerprint): OpenRouter `sk-or-v1-`/`sk-or-`, ModelScope `ms-` UUID tokens, generic
  `sk-`/`Bearer` shapes, credential-name conventions, and credential-carrying mount files.
- Reachability probe: policy-based verdicts for `public`/`allowlist`/`no-network`, plus
  an unauthenticated `GET {gateway}/models` liveness check that never sends the audited
  credential (`--offline` to skip).
- Exposure ledger as terminal text, JSON (`--json`) and Markdown (`--output report.md`).
- CI gate: any finding exits 1; clean configs exit 0.

### m3 — gate and demo: mock replacement, bilingual docs

- `benchgate gate`: local OpenAI-compatible mock gateway (models, chat/completions,
  completions, key, provider-shaped 404 elsewhere), in-place config rewrite to the mock
  key/URL, re-verification that no real credential shape or gateway host remains, eval
  execution with `BENCHGATE_MOCK_URL` injected, and crash-safe restore of the original
  config (including `--dry-run` and `--listen`).
- Demo cast recorded from real runs (`docs/demo/benchgate-audit.cast`, asciinema v2,
  script in `docs/demo/record.sh`) and a bilingual README (Chinese primary,
  `README.en.md` sibling).
- CI (`build`/`vet`/`test`) and tag-triggered release via goreleaser
  (linux/darwin × amd64/arm64 tarballs + checksums).
