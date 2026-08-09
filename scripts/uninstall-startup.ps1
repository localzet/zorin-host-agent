$ErrorActionPreference = 'SilentlyContinue'
& schtasks.exe /Delete /F /TN 'ZorinTrustHostAgent' | Out-Null
Get-Process 'zorin-host-agent' | Stop-Process -Force
Write-Host 'Zorin Trust startup agent removed. Pairing keys were intentionally kept in LocalAppData\ZorinTrust.'
