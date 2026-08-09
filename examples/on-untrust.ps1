# Safe demo hook: revoke the owner-present marker.
$marker = Join-Path $env:LOCALAPPDATA 'ZorinTrust\owner-present'
Remove-Item -Force -ErrorAction SilentlyContinue $marker
Write-Host 'Zorin owner presence revoked.'
