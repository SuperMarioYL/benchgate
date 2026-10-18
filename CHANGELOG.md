# Changelog

All notable changes to BenchGate are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

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
