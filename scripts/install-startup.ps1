$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source = Join-Path (Split-Path -Parent $Here) 'dist\zorin-host-agent-windows-amd64.exe'
if (-not (Test-Path $Source)) { throw "Host agent not found: $Source" }

$Dir = Join-Path $env:LOCALAPPDATA 'ZorinTrust\bin'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Target = Join-Path $Dir 'zorin-host-agent.exe'
Copy-Item -Force $Source $Target

$TaskName = 'ZorinTrustHostAgent'
$UserId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Do not use schtasks.exe /TR quoting here. Windows PowerShell 5.1 has awkward
# native-command quote handling and paths with spaces are easy to break.
# The ScheduledTasks API stores Execute and Arguments as separate fields.
Import-Module ScheduledTasks -ErrorAction Stop

$Action = New-ScheduledTaskAction -Execute $Target -Argument 'daemon'
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$Principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force | Out-Null

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($Task.Actions.Execute -ne $Target -or $Task.Actions.Arguments -ne 'daemon') {
    throw "Autostart verification failed: stored task action does not match the host agent."
}

# Replace any temporary/pairing daemon with the installed copy. Ignore access
# errors for unrelated sessions, then start the current user's agent hidden.
Get-Process 'zorin-host-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 250
$Started = Start-Process -WindowStyle Hidden -FilePath $Target -ArgumentList 'daemon' -PassThru

Write-Host "Installed startup agent: $Target" -ForegroundColor Green
Write-Host "Task: $TaskName" -ForegroundColor Green
Write-Host "Task action: $($Task.Actions.Execute) $($Task.Actions.Arguments)"
Write-Host "Agent PID: $($Started.Id)"
