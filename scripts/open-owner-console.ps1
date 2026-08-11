$ErrorActionPreference='Stop';
$Here=Split-Path -Parent $MyInvocation.MyCommand.Path;
$Repo=Split-Path -Parent $Here;
$arch=$env:PROCESSOR_ARCHITECTURE;
$bin=if($arch -eq 'ARM64') {
    'zorin-host-agent-windows-arm64.exe'
}
else {
    'zorin-host-agent-windows-amd64.exe'
};
$Exe=Join-Path $Repo(Join-Path 'dist' $bin);
$Demo=Join-Path $Repo 'examples\owner-console.ps1'
& $Exe gate --action owner.console --resource local:owner-console -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Demo
