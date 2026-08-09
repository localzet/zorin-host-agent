$ErrorActionPreference='Stop'
$Here=Split-Path -Parent $MyInvocation.MyCommand.Path;$Repo=Split-Path -Parent $Here;$arch=$env:PROCESSOR_ARCHITECTURE;$bin=if($arch -eq 'ARM64'){'zorin-host-agent-windows-arm64.exe'}else{'zorin-host-agent-windows-amd64.exe'};$Exe=Join-Path $Repo (Join-Path 'dist' $bin);$TaskName='ZorinTrustHostAgent'
try{Import-Module ScheduledTasks -ErrorAction Stop;$task=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue;if($null-ne$task){Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue}}catch{}
Get-Process 'zorin-host-agent' -ErrorAction SilentlyContinue|Stop-Process -Force -ErrorAction SilentlyContinue;Start-Sleep -Milliseconds 300
& $Exe identity migrate-tpm
if($LASTEXITCODE-ne0){throw 'TPM identity migration failed.'}
Write-Host '';Write-Host 'IMPORTANT: the phone will see a NEW host cryptographic identity.' -ForegroundColor Yellow;Write-Host 'Run 2-PAIR-OWNER.bat and approve the new fingerprint on the phone.' -ForegroundColor Yellow
