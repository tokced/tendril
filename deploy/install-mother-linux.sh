#!/usr/bin/env bash
# 把 Tendril 母端装成 systemd 用户服务（Linux）。
#   ./deploy/install-mother-linux.sh [--no-start]
# 环境变量可覆盖：PYTHON、TENDRIL_HOST、TENDRIL_PORT、TENDRIL_STATE
# 测试用：TENDRIL_SKIP_SYSTEMCTL=1 只写 unit，不调 systemctl。
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
python=${PYTHON:-python3}
bind_host=${TENDRIL_HOST:-0.0.0.0}
port=${TENDRIL_PORT:-8911}
state=${TENDRIL_STATE:-}
start=1
[[ "${1:-}" == "--no-start" ]] && start=0

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit="$unit_dir/tendril-mother.service"
mkdir -p "$unit_dir"

command -v "$python" >/dev/null 2>&1 || { echo "找不到 Python：$python" >&2; exit 1; }
[[ -f "$repo/mother/server.py" ]] || { echo "仓库路径不对：$repo" >&2; exit 1; }

{
  echo "[Unit]"
  echo "Description=Tendril mother (device ledger, invites, MCP control plane)"
  echo "After=network-online.target"
  echo
  echo "[Service]"
  echo "Type=simple"
  echo "WorkingDirectory=$repo"
  echo "ExecStart=$python $repo/mother/server.py serve --host $bind_host --port $port"
  echo "Environment=PYTHONUNBUFFERED=1"
  [[ -n "$state" ]] && echo "Environment=TENDRIL_STATE=$state"
  echo "Restart=on-failure"
  echo "RestartSec=3"
  echo "UMask=0077"
  echo
  echo "[Install]"
  echo "WantedBy=default.target"
} > "$unit"

echo "已写入 $unit"
if [[ "${TENDRIL_SKIP_SYSTEMCTL:-0}" != "1" ]]; then
  systemctl --user daemon-reload
  if [[ "$start" == "1" ]]; then
    systemctl --user enable --now tendril-mother.service
    systemctl --user --no-pager status tendril-mother.service || true
  else
    systemctl --user enable tendril-mother.service
  fi
  echo
  echo "开机即运行（未登录也起）：loginctl enable-linger $USER"
  echo "日志：journalctl --user -u tendril-mother -f"
fi
