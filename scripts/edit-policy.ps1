$ErrorActionPreference='Stop';
$StateDir=Join-Path $env:APPDATA 'ZorinTrust';
$Policy=Join-Path $StateDir 'policy.json';
if(-not(Test-Path $Policy)) {
    throw 'policy.json does not exist yet; start Host Agent once first.'
};
Start-Process notepad.exe -ArgumentList $Policy
