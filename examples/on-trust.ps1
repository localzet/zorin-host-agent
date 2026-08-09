# Safe demo hook: create an owner-present marker and optionally start your own private tool.
$dir = Join-Path $env:LOCALAPPDATA 'ZorinTrust'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -Path (Join-Path $dir 'owner-present') -Value ([DateTimeOffset]::Now.ToString('O'))
Write-Host 'Zorin owner presence established.'

# Example integration point (disabled):
# Start-Process 'C:\Path\To\Your\PrivateAdminConsole.exe'
