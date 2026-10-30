# ==============================================================================
# SENTRIX - Unified Build Orchestrator (PowerShell for Windows)
# Builds Core and containerized engine images
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$CoreOnly,
    [switch]$ContainersOnly
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "=== SENTRIX Unified Multi-Engine Build Orchestrator ===" -ForegroundColor Cyan

# 1. Build Core if Go is present
if (-not $ContainersOnly) {
    $goCmd = Get-Command go -ErrorAction SilentlyContinue
    if ($goCmd) {
        & "$ScriptDir\build-core.ps1"
    } else {
        Write-Host "NOTICE: Native Go not found. Core will be built via Docker." -ForegroundColor Yellow
    }
}

if ($CoreOnly) {
    exit 0
}

# 2. Check Docker
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Error "Docker executable is not installed or not in PATH."
    exit 1
}

$dockerInfo = & docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Docker daemon is not running."
    Write-Host "Please start Docker Desktop (WSL2 engine) to build containerized images." -ForegroundColor Yellow
    exit 1
}

Push-Location $RootDir
try {
    Write-Host "Building Docker images for SENTRIX stack..." -ForegroundColor Cyan
    & docker compose -f deploy\docker-compose.yml build
    if ($LASTEXITCODE -ne 0) { throw "Docker compose build failed" }
    Write-Host "=== Docker compose build complete ===" -ForegroundColor Green
} finally {
    Pop-Location
}
