<#
.SYNOPSIS
  把 Tendril 母端装成登录时自启的计划任务（Windows）。

.DESCRIPTION
  以当前用户身份运行，不需要管理员。任务在登录后启动；未登录时不会运行。
  状态目录默认 %LOCALAPPDATA%\Tendril，日志写到 <state>\mother.log。

  Windows 要在无人登录时也常驻，需要管理员把母端装成服务（例如 NSSM 或
  WinSW）；本脚本不代做，避免把用户态状态目录和服务账户混在一起。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\install-mother-windows.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\install-mother-windows.ps1 -Uninstall
#>
param(
  [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$Python = "python",
  [string]$BindHost = "0.0.0.0",
  [int]$Port = 8911,
  [string]$State = (Join-Path $env:LOCALAPPDATA "Tendril"),
  [string]$TaskName = "tendril-mother",
  [switch]$Uninstall,
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
  $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($null -eq $existing) { Write-Host "没有计划任务 $TaskName"; exit 0 }
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host "已卸载计划任务 $TaskName（状态目录与日志保留：$State）"
  exit 0
}

$server = Join-Path $Repo "mother\server.py"
if (-not (Test-Path $server)) { throw "仓库路径不对：$Repo" }
$pythonCmd = Get-Command $Python -ErrorAction SilentlyContinue
if ($null -eq $pythonCmd) { throw "找不到 Python：$Python（用 -Python 指定完整路径）" }

New-Item -ItemType Directory -Force -Path $State | Out-Null
$log = Join-Path $State "mother.log"

# 计划任务不会重定向输出：在 PowerShell 里起进程并把 stdout/stderr 追加到日志。
$inner = "`$env:TENDRIL_STATE='$State'; `$env:PYTHONUNBUFFERED='1'; `$env:PYTHONUTF8='1'; " +
         "& '$($pythonCmd.Source)' '$server' serve --host '$BindHost' --port $Port " +
         "*>> '$log'"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -Command `"$inner`"" `
  -WorkingDirectory $Repo
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -Settings $settings -Description "Tendril mother (device control plane)" -Force | Out-Null

if (-not $NoStart) {
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 1
  Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo |
    Format-List TaskName, LastRunTime, LastTaskResult
}

Write-Host ""
Write-Host "已安装计划任务 $TaskName"
Write-Host "  状态目录: $State"
Write-Host "  日志:     $log"
Write-Host "  卸载:     powershell -ExecutionPolicy Bypass -File deploy\install-mother-windows.ps1 -Uninstall"
