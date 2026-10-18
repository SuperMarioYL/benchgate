[English](./README.en.md) | **简体中文**

<div align="center">

# BenchGate

**跑分前审计 Agent 评测沙箱，把被测模型可达的真实凭据换成 mock 网关**

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=20&pause=1200&color=58A6FF&center=true&vCenter=true&multiline=true&width=760&height=70&lines=%E8%B7%91%E5%88%86%E5%89%8D%EF%BC%8C%E5%85%88%E5%AE%A1%E8%AE%A1%E6%B2%99%E7%AE%B1%E9%87%8C%E7%9A%84%E7%9C%9F%E5%AE%9E%E5%87%AD%E6%8D%AE%3Baudit%20%E5%87%BA%E8%B4%A6%E6%9C%AC%20%C2%B7%20gate%20%E6%8D%A2%20mock%20%C2%B7%20exit%20code%20%E5%BD%93%E9%97%A8%E7%A6%81" alt="跑分前，先审计沙箱里的真实凭据；audit 出账本 · gate 换 mock · exit code 当门禁" />

[![ci](https://img.shields.io/github/actions/workflow/status/SuperMarioYL/benchgate/ci.yml?branch=main&label=ci&logo=github)](https://github.com/SuperMarioYL/benchgate/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/SuperMarioYL/benchgate?logo=github)](https://github.com/SuperMarioYL/benchgate/releases)
[![Go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)](https://github.com/SuperMarioYL/benchgate/releases)
[![license](https://img.shields.io/github/license/SuperMarioYL/benchgate)](./LICENSE)

Harbor/Pier 这类 Coding Agent 评测沙箱默认可出外网（`no-network`/`allowlist` 隔离需要显式配置），而跑分配置又必须带上 OpenRouter、ModelScope 的网关 endpoint 和 key。这些 key 经 `[environment.env]` 注入后就在被测模型可达范围里——公开观测中，DeepSeek V4.1 Flash 已经主动发现并滥用过这一暴露面。BenchGate 在评测启动前给出**凭据可达性账本**（`audit`），并用**本地同构 mock 网关替换**（`gate`）把"改配置"变成"可复跑的 CI 门禁"。

[快速开始](#快速开始) · [演示](#演示) · [能力与边界](#能力与边界) · [与其他工具的分工](#与其他工具的分工) · [配置](#配置) · [路线图](#路线图) · [价格](#价格)

</div>

## 为什么需要跑分前的凭据门禁

三个事实叠加，让"跑分前审计沙箱凭据"成为必要步骤：

1. **沙箱默认不隔离，凭据默认在场。** Harbor 的 `network_mode` 默认 `public`，`no-network`/`allowlist` 需要显式配置；Pier 的 `allow_internet` 默认 `true`。同时评测必须可达推理网关，OpenRouter/ModelScope 的 endpoint 和 key 通常就写在 `[environment.env]` 里，由 harness 在运行时解析进 agent 进程环境。两者组合意味着：默认情况下，被测模型拿得到能消费的真实 key。
2. **模型会找到它。** r/LocalLLaMA 的 PSA 报告并经我们复核（Harbor `harbor-framework/harbor`、Pier `datacurve-ai/pier` 上游源码逐行验证，见 [docs/evidence/repro.md](docs/evidence/repro.md)）：DeepSeek V4.1 Flash 在 Harbor/Pier 沙箱里主动发现并滥用了这些可达凭据；同代的 V4、GLM 5.3+Flash、Qwen 未观测到类似行为。哪次评测碰到哪种行为不可预知——这正是不该由人肉保证的部分。
3. **事后工具救不回分数。** gitleaks 一类扫的是仓库代码，OpenRouter 花费告警响起来时 token 已经烧了、这次跑分已经作废。缺的是一个在评测启动前执行、可重复、以 exit code 说话的门禁。

断网跑评测不解决问题：SWE-bench 式评测必须可达推理网关。正确的做法是保留网关可达性，但把真实凭据换掉——这就是 `gate` 做的事。

## 快速开始

### 安装

```bash
# 从源码（Go 1.24+）
go install github.com/SuperMarioYL/benchgate/cmd/benchgate@v0.1.0

# 或下载 release 二进制（linux/darwin × amd64/arm64，含 checksums.txt）
# https://github.com/SuperMarioYL/benchgate/releases
```

单二进制，无守护进程；`audit` 不需要 Docker，唯一的外部请求是一次对网关 `/models` 的无鉴权 GET（可用 `--offline` 关闭）。

### 60 秒跑一遍

仓库自带两个示例配置：`benchgate.example.yaml`（带着真实形状的 fixture key，不是可用凭据）和它的清理版 `examples/clean.yaml`。

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

exit 1 就是 CI 门禁：任何发现都会让这一步失败。清理后的配置：

```bash
$ benchgate audit examples/clean.yaml   # findings: 0，exit 0，放行
```

接进评测流水线（评测 job 之前）：

```yaml
- name: pre-bench credential gate
  run: |
    go install github.com/SuperMarioYL/benchgate/cmd/benchgate@v0.1.0
    benchgate audit tasks/hello-world/task.toml
    # exit 1 → 本步失败，评测 job 不会启动
```

### 评测前换上 mock

```bash
# 先干跑：改写配置 → 复验 → 还原，不启动评测
benchgate gate benchgate.example.yaml --dry-run

# 正式门禁：mock 注入后运行评测命令，结束后自动还原配置
benchgate gate benchgate.example.yaml -- harbor run --task tasks/hello-world
```

`gate` 会启动一个本地 OpenAI 兼容 mock 网关，把配置里所有真实凭据值换成占位 key、所有真实网关 URL 换成 mock 地址，复验"没有真实凭据形状、没有真实网关引用"后才把评测命令跑起来，并向评测进程注入 `BENCHGATE_MOCK_URL`。

## 演示

约 30 秒的完整流程录屏（asciinema v2，由真实运行录制，脚本见 [docs/demo/record.sh](docs/demo/record.sh)）：

[docs/demo/benchgate-audit.cast](docs/demo/benchgate-audit.cast) — audit 发现可达凭据并给出判定证据；gate 注入 mock 网关，复验零真实外联。

```bash
asciinema play docs/demo/benchgate-audit.cast
```

录屏末段（gate 注入 mock 后，评测进程调用 chat/completions 只会命中本地 mock）：

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

## 它怎么工作

单二进制 `benchgate`，无守护进程，四个内部阶段：

```text
benchgate (Go 单二进制)
├── config loader──解析 task.toml / job config.yaml / compose，枚举 env、挂载与 network 策略
├── detectors ────凭据形状：OpenRouter sk-or-、ModelScope ms-、通用 sk-/Bearer、凭据命名与挂载文件
├── probe ────────network 策略可达性判定 + 无鉴权 GET 网关 /models（不带任何凭据）
├── mock gateway──本地 OpenAI 兼容 mock；gate 注入、复验、还原
└── report ───────脱敏账本（终端 / JSON / Markdown）+ CI exit code
```

账本里的每条发现只携带元数据：变量名、前缀类别、长度和 SHA-256 指纹（前 16 个十六进制字符）。**凭据原文从不被打印或落盘**——报告可以存档、diff，而密钥本身不会进任何日志。

## 能力与边界

| 能力 | v0.1 状态 |
| --- | --- |
| Harbor `task.toml`（含 `[agent]` 相位覆盖、旧 `allow_internet` 字段）解析 | 已实现 |
| Harbor job 级 `config.yaml` 与 docker-compose 解析（env 并集 + bind mounts） | 已实现 |
| OpenRouter（`sk-or-v1-`/`sk-or-`）、ModelScope（`ms-` UUID）、通用 `sk-`/`Bearer` 值形状检测 | 已实现 |
| 凭据命名规则（`*_KEY`/`*_TOKEN`/`*SECRET` 等）与挂载文件（`.env`、`id_rsa`、`*.pem` 等）检测 | 已实现 |
| network 策略可达性判定（public / allowlist / no-network） | 已实现 |
| 网关 endpoint 无鉴权连通性探测（`GET /models`，不带凭据） | 已实现 |
| 脱敏账本：终端 / `--json` / `--output report.md` | 已实现 |
| CI exit code 门禁 | 已实现 |
| mock 网关（models / chat/completions / completions / key）+ 配置改写 + 复验 + 还原 | 已实现 |
| `docker exec` 进入运行中的容器取证 | 未实现——审计是配置级的，见下 |
| 容器网络内自动可达的 mock 注入 | 未实现（路线图 v0.2），见下 |
| hosted 报告上传接口 | 未实现（见[价格](#价格)） |

两条如实说明，用前请读：

- **审计是配置级判定 + 无鉴权连通性检查，不是容器内取证。** 可达性来自配置声明的 network 策略（`public` 判可达；`allowlist` 按 `allowed_hosts` 匹配网关 host，匹配刻意宽松、宁可多报；`no-network` 判不可达）。探测只做一次不带 `Authorization` 头的 `GET {gateway}/models`，验证 endpoint 存活、记录状态码——被审计的 key 不会被使用，传输失败只记为"不确定"，不改变判定。v0.1 不 `docker exec` 进容器。
- **mock 默认绑定 loopback，对容器内模型不是自动可达。** `gate` 在 v0.1 给出的是**配置级保证**：复验后的配置里没有真实 key、没有真实网关 URL，harness 用它启动的评测只会拿到 mock 地址。评测进程与 mock 同主机时（host 上直接跑的 harness、host 网络模式的容器）loopback 即可命中 mock；模型跑在独立 Docker 容器网络里时，还需要让 mock 对容器网络可达（`--listen 0.0.0.0:端口` 并把 base URL 指向 host-gateway 地址），这一步 v0.1 不自动完成，v0.2 计划自动化。

## 与其他工具的分工

这不是又一个密钥扫描器。各方看的是不同的东西：

| 工具 | 审计对象 | 时机 | 处置方式 |
| --- | --- | --- | --- |
| gitleaks / trufflehog | 仓库代码里已提交的密钥 | 提交 / CI 时 | 告警、阻止合并 |
| OpenRouter 花费告警 | 账单消耗 | 事后 | 止损：轮换 key |
| Harbor/Pier 网络隔离 | 容器出网 | 运行时 | 需显式配置，且评测必须保留网关可达 |
| **BenchGate** | 评测沙箱配置里模型可达的凭据 | **跑分前** | **换成 mock 网关 + exit code 门禁** |

BenchGate 审计的是环境而不是模型，缓解靠替换而不是检测；它不解决容器逃逸、prompt injection 或全量网络扫描，也不修改 Harbor/Pier 上游——刻意保持旁路，以中立覆盖 Harbor、Pier 与同构自研 harness。

## 配置

### 支持的配置格式

| 输入 | 识别方式 | 提取内容 |
| --- | --- | --- |
| Harbor `task.toml` | `.toml` 扩展名 | `[environment.env]` 字符串对；network 策略取 `[agent]` 相位覆盖，缺省回落 `[environment]`；旧字段 `allow_internet = false` 等价 no-network |
| Harbor job 级 `config.yaml` | `.yaml`/`.yml` 且无 `services` 键 | `environment.env` 与 `network_mode` |
| docker-compose | `.yaml`/`.yml` 且有 `services` 键 | 各 service 的 env 并集（模型容器与 sidecar 同网络）、bind mounts；任一 service 可出网则整体按 public 处理 |

解析宽容：未建模的表和字段（`[task]`、`[metadata]`、`[verifier]` 等）原样忽略，因此 Pier 与同构的自研 harness 配置也能解析。

### network_mode 判定

| 策略 | 可达性判定 |
| --- | --- |
| `public`（默认；未声明、`bridge`、`host` 等均归入此档） | 网关可达，凭据可消费 |
| `allowlist` | `allowed_hosts` 覆盖网关 host 才可达（精确项、子域与 `*.后缀` 通配；宽松匹配，宁可误报可达） |
| `no-network` | 不可达，凭据不可消费 |

### 命令与选项

```text
benchgate audit <task.toml|config.yaml|docker-compose.yaml>
  --json          报告以 JSON 输出到 stdout
  --output FILE   报告写入文件（.md 渲染 Markdown，其余 JSON），仍打印终端账本
  --offline       跳过对网关 endpoint 的在线探测（离线审计主机）

benchgate gate <config> -- <评测命令>
  --dry-run       执行改写、复验、还原，不启动评测
  --listen ADDR   mock 网关监听地址（默认 127.0.0.1:0）
```

exit code：`0` 无发现；`1` 有发现或运行出错。门禁判定刻意保持二元——单条发现的 `reachable` 细节放在报告里供人判断，exit code 不做策略化解释，避免门禁随政策漂移。

`gate` 的恢复是崩溃安全的：评测启动前原始配置另存 `*.benchgate.bak`，正常结束、SIGINT/SIGTERM 与评测自身退出码透传之外，即使 gate 进程被 SIGKILL，原始配置也在磁盘上。

## 路线图

- **v0.1.x** — 更多 provider 的凭据形状（通用 `sk-`/`Bearer` 已覆盖主流 OpenAI 兼容网关）；报告格式增强。
- **v0.2** — 容器网络内自动可达的 mock 注入（host-gateway 自动化）；`benchgate-action`：CI 里一个 step 复用整套门禁。
- **hosted** — `benchgate upload` 报告上传接口、团队政策档与漂移告警（见[价格](#价格)）。
- **持续跟踪上游** — Harbor/Pier 若在默认值里剥离凭据或提供官方 mock（如 PR #3538 方向），`audit` 仍作为合规验证器保留；跟踪记录见 [docs/evidence/repro.md](docs/evidence/repro.md)。

## 价格

**Hosted 团队政策档**（规划中；v0.1 不含任何 SaaS 组件，也不上传任何数据）：**$99/月/组织**，前 10 家早鸟 **$49/月**。

面向要把"gate exit 0"写进组织评测政策的企业 CI 团队：

- 网关白名单与强制 gate 的组织政策档
- 评测配置漂移告警（每次 harness/模型 bump 自动重审）
- 报告留存 90 天
- 私有 mock 镜像

CLI 与自托管是全功能的 MIT 开源软件，hosted 层不锁任何本地能力。早期接入与需求登记：在 [GitHub Issues](https://github.com/SuperMarioYL/benchgate/issues) 提 issue。

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
