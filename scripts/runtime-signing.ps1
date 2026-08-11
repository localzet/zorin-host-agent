function Get-ZorinSdkRoot {
    $candidates=@()
    if($env:ANDROID_SDK_ROOT) {
        $candidates += $env:ANDROID_SDK_ROOT
    }
    if($env:ANDROID_HOME) {
        $candidates += $env:ANDROID_HOME
    }
    if($env:LOCALAPPDATA) {
        $candidates +=(Join-Path $env:LOCALAPPDATA 'Android\Sdk')
    }
    foreach($c in $candidates) {
        if($c -and(Test-Path $c)) {
            return(Resolve-Path $c).Path
        }
    }
    throw 'Android SDK not found. Expected ANDROID_SDK_ROOT/ANDROID_HOME or %LOCALAPPDATA%\Android\Sdk.'
}
function Get-ZorinApkSigner {
    $sdk=Get-ZorinSdkRoot
    $bt=Join-Path $sdk 'build-tools'
    if(-not(Test-Path $bt)) {
        throw "Android SDK Build-Tools are not installed under $bt"
    }
    $items=@(Get-ChildItem $bt -Directory | Sort-Object Name -Descending)
    foreach($d in $items) {
        $p=Join-Path $d.FullName 'apksigner.bat';
        if(Test-Path $p) {
            return $p
        }
    }
    throw 'apksigner.bat not found. Install Android SDK Build-Tools from Android Studio SDK Manager.'
}
function Get-ZorinKeytool {
    $cmd=Get-Command keytool.exe -ErrorAction SilentlyContinue
    if($cmd) {
        return $cmd.Source
    }
    $cmd=Get-Command keytool -ErrorAction SilentlyContinue
    if($cmd) {
        return $cmd.Source
    }
    if($env:JAVA_HOME) {
        $p=Join-Path $env:JAVA_HOME 'bin\keytool.exe';
        if(Test-Path $p) {
            return $p
        }
    }
    $p='C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe'
    if(Test-Path $p) {
        return $p
    }
    throw 'keytool not found. Install a JDK or Android Studio.'
}
function Get-ZorinSigningState {
    if(-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is not set'
    }
    $dir=Join-Path $env:LOCALAPPDATA 'ZorinTrust\signing'
    [pscustomobject]@ {
        Dir=$dir
        KeyStore=(Join-Path $dir 'runtime-owner.p12')
        PassFile=(Join-Path $dir 'runtime-owner.pass')
        Alias='zorin-runtime-owner'
    }
}
function Test-ZorinPassFile([string]$Path) {
    if(-not(Test-Path -LiteralPath $Path)) {
        return $false
    }
    try {
        $raw=[System.IO.File]::ReadAllText($Path,[System.Text.Encoding]::ASCII)
        return(-not [string]::IsNullOrWhiteSpace($raw))
    }
    catch {
        return $false
    }
}
function Ensure-ZorinOwnerSigner {
    $s=Get-ZorinSigningState
    New-Item -ItemType Directory -Force -Path $s.Dir | Out-Null
    $hasKey=Test-Path -LiteralPath $s.KeyStore
    $hasPass=Test-ZorinPassFile $s.PassFile
    if($hasKey -and $hasPass) {
        return $s
    }
    # Никогда молча не заменяем половину owner-managed signing identity: иначе
    # сломаем непрерывность Android APK updates. Восстановление владелец делает явно.
    if($hasKey -xor $hasPass) {
        throw "Owner signer state is incomplete under $($s.Dir). Do not delete the surviving file; restore the missing runtime-owner.p12/runtime-owner.pass before continuing."
    }
    $keytool=Get-ZorinKeytool
    $bytes=New-Object byte[] 32
    $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $pw=-join($bytes | ForEach-Object {
        $_.ToString('x2')
    }
    )
    # Файлы паролей apksigner построчные. Оставляем ровно одну строку пароля.
    [System.IO.File]::WriteAllText($s.PassFile,$pw + [Environment]::NewLine,[System.Text.Encoding]::ASCII)
    & $keytool `
        -genkeypair `
        -alias $s.Alias `
        -keyalg RSA `
        -keysize 3072 `
        -sigalg SHA256withRSA `
        -validity 36500 `
        -dname 'CN=Zorin Trust Runtime Owner Signer,O=Local Owner Development' `
        -storetype PKCS12 `
        -keystore $s.KeyStore `
        -storepass $pw `
        -keypass $pw | Out-Null
    if($LASTEXITCODE-ne0) {
        throw 'keytool failed to create owner signing key'
    }
    # Ужесточаем ACL по возможности. Ошибка не фатальна: LocalAppData и так изолирован по пользователю.
    try {
        $who=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $s.Dir /inheritance:r /grant:r "${who}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
    }
    catch {
    }
    Write-Host "Created persistent OWNER-MANAGED Android signer: $($s.KeyStore)" -ForegroundColor Green
    Write-Host 'This private key stays on this laptop and is never placed in the Git repositories.' -ForegroundColor Cyan
    return $s
}
function Sign-ZorinRuntime([string]$UnsignedApk,[string]$OutputApk) {
    if(-not(Test-Path $UnsignedApk)) {
        throw "Unsigned APK missing: $UnsignedApk"
    }
    $s=Ensure-ZorinOwnerSigner
    $apksigner=Get-ZorinApkSigner
    if(Test-Path $OutputApk) {
        Remove-Item -Force $OutputApk
    }
    # ВАЖНО: не передаём один и тот же однострочный password-файл одновременно в --ks-pass
    # и --key-pass. apksigner читает записи последовательно и попытается взять вторую строку
    # для пароля ключа. В сгенерированном PKCS12 пароль ключа совпадает с паролем хранилища,
    # поэтому без --key-pass apksigner корректно переиспользует пароль keystore.
    & $apksigner sign --ks $s.KeyStore --ks-key-alias $s.Alias --ks-pass "file:$($s.PassFile)" --out $OutputApk $UnsignedApk
    if($LASTEXITCODE-ne0) {
        throw 'apksigner sign failed'
    }
    & $apksigner verify --verbose --print-certs $OutputApk
    if($LASTEXITCODE-ne0) {
        throw 'apksigner verify failed'
    }
    return $OutputApk
}
