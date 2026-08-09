$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source = Join-Path (Split-Path -Parent $Here) 'dist\zorin-host-agent-windows-amd64.exe'
if (-not (Test-Path $Source)) { throw "Host agent not found: $Source" }
$Dir = Join-Path $env:LOCALAPPDATA 'ZorinTrust\bin'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Target = Join-Path $Dir 'zorin-host-agent.exe'
Copy-Item -Force $Source $Target
$TaskName = 'ZorinTrustHostAgent'
$Ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Action = "`"$Ps`" -NoProfile -WindowStyle Hidden -Command `"& '`'$Target'`' daemon`""
& schtasks.exe /Create /F /SC ONLOGON /TN $TaskName /TR $Action | Out-Host
Start-Process -WindowStyle Hidden -FilePath $Target -ArgumentList 'daemon'
Write-Host "Installed startup agent: $Target" -ForegroundColor Green
Write-Host "Task: $TaskName"
