# ==============================================================================
# SENTRIX - Development Cluster Runner (PowerShell for Windows)
# Launches lightweight dev profile (Core, Coraza WAF, CrowdSec, Promptfoo)
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$Foreground,
    [switch]$Down
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Push-Location $RootDir
try {
    if ($Down) {
        Write-Host "Stopping SENTRIX cluster..." -ForegroundColor Yellow
        & docker compose -f deploy\docker-compose.yml -f deploy\docker-compose.dev.yml down
        exit 0
    }

    Write-Host "=== Launching SENTRIX Development Cluster ===" -ForegroundColor Cyan
    Write-Host "Services: sentrix-core, sentrix-waf-coraza, sentrix-crowdsec, sentrix-promptfoo`n"

    $dockerInfo = & docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker Desktop daemon is not running. Please start Docker Desktop (WSL2 engine)."
        exit 1
    }

    $composeArgs = @("-f", "deploy\docker-compose.yml", "-f", "deploy\docker-compose.dev.yml", "up")
    if (-not $Foreground) {
        $composeArgs += "-d"
    }

    & docker compose $composeArgs
    if ($LASTEXITCODE -ne 0) { throw "Docker compose up failed" }

    Write-Host "`n=== SENTRIX Development Cluster Active ===" -ForegroundColor Green
    Write-Host " • Ingress WAF Proxy: http://localhost:8080" -ForegroundColor White
    Write-Host " • SENTRIX Core API:  http://localhost:9000/api/v1/health" -ForegroundColor White
    Write-Host " • CrowdSec LAPI:     http://localhost:8085/v1/health" -ForegroundColor White
    Write-Host " • Promptfoo Web UI:  http://localhost:15500" -ForegroundColor White
    Write-Host "`nFollow logs with: docker compose -f deploy\docker-compose.yml logs -f" -ForegroundColor Gray
} finally {
    Pop-Location
}
