#!/bin/bash
# Recording script for docs/demo/benchgate-audit.cast.
#
# Every command shown in the cast is executed for real against the built
# binary; the dim lines are annotations, nothing else is scripted output.
#
# Reproduce with:
#   go build -o bin/benchgate ./cmd/benchgate
#   asciinema rec --headless --overwrite --output-format asciicast-v2 \
#     --idle-time-limit 2.5 --window-size 150x36 \
#     --title "benchgate audit: find the model-reachable OpenRouter key in 30 seconds" \
#     --command "bash docs/demo/record.sh" docs/demo/benchgate-audit.cast
set -u
cd "$(dirname "$0")/../.." || exit 1
export PATH="$PWD/bin:$PATH"
export TERM=xterm-256color

dim()    { printf '\x1b[2m%s\x1b[0m\r\n' "$1"; }
prompt() { printf '\r\n\x1b[1;32m$\x1b[0m \x1b[1m%s\x1b[0m\r\n' "$1"; }

sleep 0.8

prompt 'benchgate --version'
benchgate --version

sleep 1.5
dim '# 跑分前的 Harbor 评测配置：audit 给出暴露账本，exit 1 让 CI 拦下评测'
prompt 'benchgate audit benchgate.example.yaml'
benchgate audit benchgate.example.yaml
dim '# exit code 1 —— 凭据可达，评测被拦截'

sleep 1.5
dim '# 清理后的同一配置：没有凭据形状，exit 0 放行'
prompt 'benchgate audit examples/clean.yaml'
benchgate audit examples/clean.yaml
dim '# exit code 0'

sleep 1.5
dim '# gate：真实凭据与网关 URL 全部换成同构 mock，复验后还原配置'
prompt 'benchgate gate benchgate.example.yaml --dry-run'
benchgate gate benchgate.example.yaml --dry-run

sleep 1.5
dim '# 评测进程能命中的只有本地 mock —— 不产生任何真实网关调用'
eval_cmd='benchgate gate benchgate.example.yaml -- bash -c '"'"'curl -s -X POST $BENCHGATE_MOCK_URL/chat/completions -d "{\"model\":\"deepseek-v4.1-flash\"}"'"'"''
prompt "$eval_cmd"
eval "$eval_cmd"
dim '# 响应来自本地 mock 网关；gateway served 1 request(s)'

sleep 1.2
