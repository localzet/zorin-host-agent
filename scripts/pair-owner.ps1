$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path (Split-Path -Parent $Here) 'dist\zorin-host-agent-windows-amd64.exe'
if (-not (Test-Path $Exe)) { throw "Host agent not found: $Exe" }
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) { throw 'adb is not in PATH. Install Android Platform Tools first.' }
$devices = @()
adb devices | Select-Object -Skip 1 | ForEach-Object {
    $f = ($_ -split '\s+') | Where-Object { $_ }
    if ($f.Count -ge 2 -and $f[1] -eq 'device') { $devices += $f[0] }
}
if ($devices.Count -ne 1) { throw "Pairing expects exactly one authorized adb device; found $($devices.Count)." }
$serial = $devices[0]
Write-Host "Starting one-time owner pairing window for $serial" -ForegroundColor Cyan
Write-Host 'The app will open. Go to TRUST and tap APPROVE HOST when the fingerprint is shown.'
& $Exe daemon --pair-once --serial $serial
