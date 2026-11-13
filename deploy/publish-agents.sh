#!/usr/bin/env bash
# 构建三个平台的子端到母端投递目录（邀请短链接从这里下载）。
#   ./deploy/publish-agents.sh                 # 状态目录取母端默认值
#   TENDRIL_STATE=~/.local/state/tendril ./deploy/publish-agents.sh
# 产物：deliver/agent.exe、agent-linux、agent-darwin 及各自的 .sha256
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

state=${TENDRIL_STATE:-$(python3 - <<'PY'
import sys
sys.path.insert(0, "mother")
import server  # noqa: E402  只读默认路径，不会启动服务
print(server.STATE)
PY
)}
out="$state/deliver"
mkdir -p "$out"

command -v go >/dev/null 2>&1 || { echo "需要 Go 1.26+ 来构建子端" >&2; exit 1; }

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

build() {
  local goos=$1 goarch=$2 name=$3
  echo "构建 $goos/$goarch → $name"
  (cd agent/go && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
     go build -trimpath -ldflags "-s -w" -o "$out/$name" .)
  ( cd "$out" && sha "$name" > "$name.sha256" )
}

build linux  amd64 agent-linux
build windows amd64 agent.exe
build darwin arm64  agent-darwin

echo
echo "已写入 ${out}："
ls -l "$out"/agent* | awk '{print "  " $5 "  " $9}'
echo
echo "现在可以生成一键邀请：python3 mother/server.py invite <device> --url https://<mother>:8911"
