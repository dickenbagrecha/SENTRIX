# ==============================================================================
# SENTRIX - Core Build Script (PowerShell for Windows)
# Compiles sentrixd orchestrator daemon and sentrix-waf reverse proxy
# ==============================================================================

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$CoreDir = Join-Path $RootDir "core"
$BinDir = Join-Path $RootDir "bin"

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

Write-Host "=== Building SENTRIX Core Binaries ===" -ForegroundColor Cyan

$goCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCmd) {
    Write-Warning "Go toolchain ('go.exe') is not found in PATH."
    Write-Host "You can compile Core inside Docker using:" -ForegroundColor Yellow
    Write-Host "  docker build -f deploy/docker/Dockerfile.core -t sentrix-core ." -ForegroundColor White
    exit 1
}

Push-Location $CoreDir
try {
    Write-Host "Compiling sentrixd daemon..." -ForegroundColor Cyan
    & go build -ldflags="-w -s" -o "$BinDir\sentrixd.exe" .\cmd\sentrixd
    if ($LASTEXITCODE -ne 0) { throw "Failed to build sentrixd" }
    Write-Host " [OK] Built $BinDir\sentrixd.exe" -ForegroundColor Green

    Write-Host "Compiling sentrix-waf proxy..." -ForegroundColor Cyan
    & go build -ldflags="-w -s" -o "$BinDir\sentrix-waf.exe" .\cmd\sentrix-waf
    if ($LASTEXITCODE -ne 0) { throw "Failed to build sentrix-waf" }
    Write-Host " [OK] Built $BinDir\sentrix-waf.exe" -ForegroundColor Green

    Write-Host "`nRunning Core unit tests..." -ForegroundColor Cyan
    & go test -v .\tests\...
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed" }
    Write-Host " [OK] All Core unit tests passed." -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host "=== SENTRIX Core build complete ===" -ForegroundColor Green
