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
$Source = Join-Path $Repo(Join-Path 'dist' $bin)
if(-not(Test-Path $Source)) {
    throw "Host agent not found: $Source"
}
$AdbCmd=Get-Command adb.exe -ErrorAction SilentlyContinue;
if($null-eq$AdbCmd) {
    $AdbCmd=Get-Command adb -ErrorAction SilentlyContinue
};
if($null-eq$AdbCmd) {
    throw 'adb is not available. Install Android platform-tools or add adb.exe to PATH, then rerun this installer.'
};
$AdbPath=$AdbCmd.Source;
if(-not$AdbPath) {
    $AdbPath=$AdbCmd.Path
};
if(-not(Test-Path $AdbPath)) {
    throw "Resolved adb path does not exist: $AdbPath"
}
$TaskName='ZorinTrustHostAgent';
$StateDir=Join-Path $env:APPDATA 'ZorinTrust';
$InstallRoot=Join-Path $env:LOCALAPPDATA 'ZorinTrust';
$Dir=Join-Path $InstallRoot 'bin';
$Target=Join-Path $Dir 'zorin-host-agent.exe';
$UserId=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Import-Module ScheduledTasks -ErrorAction Stop;
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$ExistingTask=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue;
if($null-ne$ExistingTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
$pids=@();
try {
    $pids=@(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 47472 -State Listen -ErrorAction Stop|Select-Object -ExpandProperty OwningProcess -Unique)
}
catch {
};
if($pids.Count-gt0) {
    Write-Host "Stopping $($pids.Count) existing agent process(es) before update..." -ForegroundColor Yellow;
    $pids|ForEach-Object {
        Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
    };
    Start-Sleep -Milliseconds 300
}
Remove-Item(Join-Path $StateDir 'session.json') -Force -ErrorAction SilentlyContinue;
Remove-Item(Join-Path $StateDir 'owner-mode.json') -Force -ErrorAction SilentlyContinue
Copy-Item -Force $Source $Target
$TaskArgs='daemon --adb "'+$AdbPath+'"';
$Action=New-ScheduledTaskAction -Execute $Target -Argument $TaskArgs;
$Trigger=New-ScheduledTaskTrigger -AtLogOn -User $UserId;
$Principal=New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited;
$Settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force|Out-Null
$Task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop;
if($Task.Actions.Execute-ne$Target-or$Task.Actions.Arguments-ne$TaskArgs) {
    throw 'Autostart verification failed.'
}
$Started=Start-Process -WindowStyle Hidden -FilePath $Target -ArgumentList @('daemon','--adb',('"{0}"' -f $AdbPath)) -PassThru;
Start-Sleep -Milliseconds 500;
if($Started.HasExited) {
    throw "Host agent exited immediately with code $($Started.ExitCode)."
}
Write-Host "Installed/updated startup agent: $Target" -ForegroundColor Green;
Write-Host "Task: $TaskName";
Write-Host "ADB: $AdbPath";
Write-Host "Agent PID: $($Started.Id)"
