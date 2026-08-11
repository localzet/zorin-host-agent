$ErrorActionPreference='Stop'
$Here=Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo=Split-Path -Parent $Here
$arch=$env:PROCESSOR_ARCHITECTURE
$bin=if($arch -eq 'ARM64') {
    'zorin-host-agent-windows-arm64.exe'
}
else {
    'zorin-host-agent-windows-amd64.exe'
}
$Exe=Join-Path $Repo(Join-Path 'dist' $bin)
if(-not(Test-Path $Exe)) {
    throw "Host agent not found: $Exe"
}
& $Exe doctor
