$ErrorActionPreference = 'SilentlyContinue'
$TaskName = 'ZorinTrustHostAgent'
Import-Module ScheduledTasks -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Get-Process 'zorin-host-agent' -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host 'Zorin Trust startup agent removed. Pairing keys were intentionally kept in LocalAppData\ZorinTrust.'
