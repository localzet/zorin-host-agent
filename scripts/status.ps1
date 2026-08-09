$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path (Split-Path -Parent $Here) 'dist\zorin-host-agent-windows-amd64.exe'
& $Exe status
