$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = (Get-Command python -ErrorAction Stop).Source
}

$env:QT_QPA_PLATFORM = 'offscreen'
& $Python -m pytest -v
if ($LASTEXITCODE -ne 0) {
    throw "Tests failed with exit code $LASTEXITCODE"
}

& $Python -m compileall -q src tests scripts
if ($LASTEXITCODE -ne 0) {
    throw "Compileall failed with exit code $LASTEXITCODE"
}

& $Python -m PyInstaller --noconfirm --clean EVTXAuditor.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$Exe = Join-Path $Root 'dist\EVTXAuditor.exe'
if (-not (Test-Path -LiteralPath $Exe)) {
    throw "EXE was not created: $Exe"
}

$Process = Start-Process -FilePath $Exe -ArgumentList '--self-test' -WindowStyle Hidden -PassThru -Wait
if ($Process.ExitCode -ne 0) {
    throw "EXE self-test failed with exit code $($Process.ExitCode)"
}

Get-FileHash -Algorithm SHA256 -LiteralPath $Exe

