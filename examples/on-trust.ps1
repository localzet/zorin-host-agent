# Безопасный демонстрационный hook: ставим маркер присутствия владельца и при желании запускаем приватный инструмент.
$dir = Join-Path $env:LOCALAPPDATA 'ZorinTrust'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -Path(Join-Path $dir 'owner-present') -Value([DateTimeOffset]::Now.ToString('O'))
Write-Host 'Zorin owner presence established.'
# Пример точки интеграции (по умолчанию выключен):
# Start-Process 'C:\Path\To\Your\PrivateAdminConsole.exe'
