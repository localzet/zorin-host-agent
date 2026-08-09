$StateDir=Join-Path $env:APPDATA 'ZorinTrust';$Owner=Join-Path $StateDir 'owner-mode.json'
Clear-Host;Write-Host 'ZORIN OWNER CONSOLE' -ForegroundColor Green;Write-Host 'This demo exists only while the cryptographically verified phone session is alive.';Write-Host "Phone: $env:ZORIN_PHONE_FINGERPRINT";Write-Host "Proof: $env:ZORIN_OWNER_PROOF_FILE";Write-Host '';Write-Host 'Disconnect or lock the phone to close this console.' -ForegroundColor Yellow
while(Test-Path $Owner){Start-Sleep -Milliseconds 500}
Write-Host '';Write-Host 'OWNER TRUST LOST - closing.' -ForegroundColor Red;Start-Sleep -Seconds 1
