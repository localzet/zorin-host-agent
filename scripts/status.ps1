$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $Here
$arch = $env:PROCESSOR_ARCHITECTURE
$bin = if($arch -eq 'ARM64') {
    'zorin-host-agent-windows-arm64.exe'
}
else {
    'zorin-host-agent-windows-amd64.exe'
}
$Exe = Join-Path $Repo(Join-Path 'dist' $bin)
$TaskName = 'ZorinTrustHostAgent'
try {
    Import-Module ScheduledTasks -ErrorAction Stop
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $Info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
    Write-Host "Autostart: installed ($($Task.State))" -ForegroundColor Green
    Write-Host "  Execute: $($Task.Actions.Execute)"
    Write-Host "  Args:    $($Task.Actions.Arguments)"
    if($Info.LastRunTime -and $Info.LastRunTime.Year -gt 2000) {
        $hex =('0x{0:X8}' -f([uint32]$Info.LastTaskResult))
        $desc = switch($hex) {
            '0x00000000' {
                'success'
            }
            '0xC000013A' {
                'stopped by Ctrl+C / console close'
            }
            '0x00041306' {
                'previous scheduled-task run was terminated by user/operator'
            }
            default {
                'see Windows Task Scheduler result code'
            }
        }
        Write-Host "  Last run: $($Info.LastRunTime) / $hex ($desc)"
    }
}
catch {
    Write-Host 'Autostart: NOT INSTALLED' -ForegroundColor Yellow
}
# Имя процесса ненадёжно после копирования/переименования бинарника. Сначала ищем
# настоящий daemon по listening trust-порту, и только потом откатываемся к имени процесса.
$ids = @()
try {
    $ids = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 47472 -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess -Unique)
}
catch {
}
if($ids.Count -eq 0) {
    $ids = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -like 'zorin-host-agent*'
    }
    | Select-Object -ExpandProperty Id)
}
if($ids.Count -eq 0) {
    Write-Host 'Agent process: NOT RUNNING' -ForegroundColor Yellow
}
else {
    Write-Host "Agent process(es): $($ids.Count)" -ForegroundColor Green
    foreach($id in $ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if($null -ne $p) {
            $path='';
            try {
                $path=$p.Path
            }
            catch {
            };
            if($path) {
                Write-Host "  PID $id  $path"
            }
            else {
                Write-Host "  PID $id"
            }
        }
    }
}
& $Exe status
Write-Host 'Tip: run 11-DOCTOR.bat for live ADB/reverse/TrustService checks.' -ForegroundColor DarkGray
