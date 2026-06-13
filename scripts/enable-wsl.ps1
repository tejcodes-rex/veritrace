# Enables the Windows features Docker Desktop needs (WSL2 backend).
# Run elevated. A reboot is required afterwards, then Docker Desktop starts.
$ErrorActionPreference = "Continue"
$log = Join-Path $env:TEMP "veritrace-wsl-setup.log"
Start-Transcript -Path $log -Force | Out-Null

Write-Output "Enabling Microsoft-Windows-Subsystem-Linux..."
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart

Write-Output "Enabling VirtualMachinePlatform..."
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart

Write-Output "Updating the WSL2 kernel..."
try { wsl --update } catch { Write-Output "wsl --update: $_" }
try { wsl --set-default-version 2 } catch { Write-Output "set-default-version: $_" }

"DONE $(Get-Date -Format o)" | Out-File -FilePath (Join-Path $env:TEMP "veritrace-wsl-done.txt") -Encoding utf8
Write-Output "Features enabled. A RESTART is required before Docker Desktop can start."
Stop-Transcript | Out-Null
