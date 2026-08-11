# Безопасный демонстрационный hook: убираем маркер присутствия владельца.
$marker = Join-Path $env:LOCALAPPDATA 'ZorinTrust\owner-present'
Remove-Item -Force -ErrorAction SilentlyContinue $marker
Write-Host 'Zorin owner presence revoked.'
