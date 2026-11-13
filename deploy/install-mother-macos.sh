#!/usr/bin/env bash
# 把 Tendril 母端装成 launchd LaunchAgent（macOS，登录后自启）。
#   ./deploy/install-mother-macos.sh [--no-start]
# 环境变量可覆盖：PYTHON、TENDRIL_HOST、TENDRIL_PORT、TENDRIL_STATE
# 测试用：TENDRIL_SKIP_LAUNCHCTL=1 只写 plist，不调 launchctl。
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
python=${PYTHON:-$(command -v python3 || true)}
bind_host=${TENDRIL_HOST:-0.0.0.0}
port=${TENDRIL_PORT:-8911}
state=${TENDRIL_STATE:-$HOME/Library/Application Support/Tendril}
label="ai.tendril.mother"
plist_dir="$HOME/Library/LaunchAgents"
plist="$plist_dir/$label.plist"
log_dir="$HOME/Library/Logs/Tendril"
start=1
[[ "${1:-}" == "--no-start" ]] && start=0

[[ -n "$python" && -x "$python" ]] || { echo "找不到 python3，可用 PYTHON=... 指定" >&2; exit 1; }
[[ -f "$repo/mother/server.py" ]] || { echo "仓库路径不对：$repo" >&2; exit 1; }
mkdir -p "$plist_dir" "$log_dir"

xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "$python")</string>
    <string>$(xml_escape "$repo/mother/server.py")</string>
    <string>serve</string>
    <string>--host</string><string>$bind_host</string>
    <string>--port</string><string>$port</string>
  </array>
  <key>WorkingDirectory</key><string>$(xml_escape "$repo")</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>TENDRIL_STATE</key><string>$(xml_escape "$state")</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$(xml_escape "$log_dir/mother.log")</string>
  <key>StandardErrorPath</key><string>$(xml_escape "$log_dir/mother.log")</string>
</dict>
</plist>
EOF

echo "已写入 $plist"
if [[ "${TENDRIL_SKIP_LAUNCHCTL:-0}" != "1" ]]; then
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$plist"
  if [[ "$start" == "1" ]]; then
    launchctl kickstart -k "gui/$(id -u)/$label" || true
    launchctl print "gui/$(id -u)/$label" | sed -n '1,15p' || true
  fi
  echo
  echo "日志：tail -f \"$log_dir/mother.log\""
  echo "卸载：launchctl bootout gui/$(id -u)/$label && rm \"$plist\""
fi
