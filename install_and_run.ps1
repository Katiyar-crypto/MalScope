$ErrorActionPreference = "Stop"

$repoZip = "https://github.com/Katiyar-crypto/MalScope/archive/refs/heads/main.zip"
$installRoot = Join-Path $env:LOCALAPPDATA "MalScope"
$zipPath = Join-Path $env:TEMP "MalScope-main.zip"
$extractRoot = Join-Path $env:TEMP "MalScope-main"
$projectDir = Join-Path $installRoot "MalScope_v2.1"
$venvDir = Join-Path $installRoot ".venv"

Write-Host "==> Downloading MalScope..." -ForegroundColor Cyan
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
if (Test-Path -LiteralPath $extractRoot) {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
}
Invoke-WebRequest -Uri $repoZip -OutFile $zipPath

Write-Host "==> Installing latest files to $installRoot" -ForegroundColor Cyan
Expand-Archive -LiteralPath $zipPath -DestinationPath $env:TEMP -Force
New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
if (Test-Path -LiteralPath $projectDir) {
    Remove-Item -LiteralPath $projectDir -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $extractRoot "MalScope_v2.1") -Destination $projectDir -Recurse

Write-Host "==> Creating Python virtual environment..." -ForegroundColor Cyan
$createdVenv = $false
if (Get-Command py -ErrorAction SilentlyContinue) {
    py -3.13 -m venv $venvDir
    if ($LASTEXITCODE -eq 0) {
        $createdVenv = $true
    }
    if (-not $createdVenv) {
        py -3 -m venv $venvDir
        if ($LASTEXITCODE -eq 0) {
            $createdVenv = $true
        }
    }
}
if (-not $createdVenv -and (Get-Command python -ErrorAction SilentlyContinue)) {
    python -m venv $venvDir
    if ($LASTEXITCODE -eq 0) {
        $createdVenv = $true
    }
}
if (-not $createdVenv) {
    throw "Python 3.8+ was not found. Install Python, then run this command again."
}

$pythonExe = Join-Path $venvDir "Scripts\python.exe"
Write-Host "==> Installing dependencies..." -ForegroundColor Cyan
& $pythonExe -m pip install --upgrade pip
& $pythonExe -m pip install -r (Join-Path $projectDir "requirements.txt")

Write-Host "==> Launching MalScope..." -ForegroundColor Green
Set-Location $projectDir
& $pythonExe (Join-Path $projectDir "main.py")
