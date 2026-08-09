$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $Here
$arch = $env:PROCESSOR_ARCHITECTURE
$bin = if ($arch -eq 'ARM64') { 'zorin-host-agent-windows-arm64.exe' } else { 'zorin-host-agent-windows-amd64.exe' }
$Exe = Join-Path $Repo (Join-Path 'dist' $bin)

$TaskName = 'ZorinTrustHostAgent'
try {
    Import-Module ScheduledTasks -ErrorAction Stop
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $Info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
    Write-Host "Autostart: installed ($($Task.State))" -ForegroundColor Green
    Write-Host "  Execute: $($Task.Actions.Execute)"
    Write-Host "  Args:    $($Task.Actions.Arguments)"
    if ($Info.LastRunTime -and $Info.LastRunTime.Year -gt 2000) {
        $hex = ('0x{0:X8}' -f ([uint32]$Info.LastTaskResult))
        $desc = switch ($hex) {
            '0x00000000' { 'success' }
            '0xC000013A' { 'stopped by Ctrl+C / console close' }
            default { 'see Windows Task Scheduler result code' }
        }
        Write-Host "  Last run: $($Info.LastRunTime) / $hex ($desc)"
    }
} catch { Write-Host 'Autostart: NOT INSTALLED' -ForegroundColor Yellow }

$procs = @(Get-Process 'zorin-host-agent' -ErrorAction SilentlyContinue)
if ($procs.Count -eq 0) { Write-Host 'Agent process: NOT RUNNING' -ForegroundColor Yellow }
else {
    Write-Host "Agent process(es): $($procs.Count)" -ForegroundColor Green
    foreach ($p in $procs) { $path=''; try{$path=$p.Path}catch{}; if($path){Write-Host "  PID $($p.Id)  $path"}else{Write-Host "  PID $($p.Id)"} }
}
& $Exe status
