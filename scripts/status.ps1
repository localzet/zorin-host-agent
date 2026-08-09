$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path (Split-Path -Parent $Here) 'dist\zorin-host-agent-windows-amd64.exe'

$TaskName = 'ZorinTrustHostAgent'
try {
    Import-Module ScheduledTasks -ErrorAction Stop
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $Info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
    Write-Host "Autostart: installed ($($Task.State))" -ForegroundColor Green
    Write-Host "  Execute: $($Task.Actions.Execute)"
    Write-Host "  Args:    $($Task.Actions.Arguments)"
    if ($Info.LastRunTime -and $Info.LastRunTime.Year -gt 2000) {
        Write-Host "  Last run: $($Info.LastRunTime) / result $($Info.LastTaskResult)"
    }
} catch {
    Write-Host 'Autostart: NOT INSTALLED' -ForegroundColor Yellow
}

& $Exe status
