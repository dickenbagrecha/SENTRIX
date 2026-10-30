# ==============================================================================
# SENTRIX - ModSecurity Submodule Inspection & Fetch Script (PowerShell)
# Inspects and initializes required submodules in engines/ModSecurity-3-master
# ==============================================================================

[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$ModSecDir = Join-Path $RootDir "engines\ModSecurity-3-master"

Write-Host "=== Inspecting ModSecurity 3 Submodules ===" -ForegroundColor Cyan

if (-not (Test-Path $ModSecDir)) {
    Write-Error "ModSecurity directory not found at: $ModSecDir"
    exit 1
}

function Test-SubmoduleDir ($subPath) {
    $fullPath = Join-Path $ModSecDir $subPath
    if ((Test-Path $fullPath) -and (Get-ChildItem -Path $fullPath -Force).Count -gt 0) {
        Write-Host " [OK] Submodule directory '$subPath' is populated." -ForegroundColor Green
        return $true
    } else {
        Write-Host " [WARN] Submodule directory '$subPath' is EMPTY." -ForegroundColor Yellow
        return $false
    }
}

$libinjOk = Test-SubmoduleDir "others\libinjection"
$mbedtlsOk = Test-SubmoduleDir "others\mbedtls"
Test-SubmoduleDir "bindings\python" | Out-Null
Test-SubmoduleDir "test\test-cases\secrules-language-tests" | Out-Null

if ($libinjOk -and $mbedtlsOk) {
    Write-Host "All mandatory submodules are populated." -ForegroundColor Green
    exit 0
}

Write-Host "`nStaging missing submodules via Git..." -ForegroundColor Cyan
Push-Location $ModSecDir
try {
    $isGit = & git rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -eq 0) {
        & git submodule update --init --recursive
        Write-Host "Submodules updated via git submodule." -ForegroundColor Green
    } else {
        Write-Host "Workspace is not a submodule-linked git repo. Cloning directly into vendor stubs..." -ForegroundColor Yellow
        
        $libinjPath = Join-Path $ModSecDir "others\libinjection"
        if ((Get-ChildItem -Path $libinjPath -Force).Count -eq 0) {
            Write-Host "Cloning libinjection v4.0.0..." -ForegroundColor Cyan
            & git clone --depth 1 -b v4.0.0 https://github.com/libinjection/libinjection.git $libinjPath
        }

        $mbedtlsPath = Join-Path $ModSecDir "others\mbedtls"
        if ((Get-ChildItem -Path $mbedtlsPath -Force).Count -eq 0) {
            Write-Host "Cloning mbedtls v4.1.0..." -ForegroundColor Cyan
            & git clone --depth 1 -b v4.1.0 https://github.com/Mbed-TLS/mbedtls.git $mbedtlsPath
        }

        $tfPath = Join-Path $mbedtlsPath "tf-psa-crypto"
        if (-not (Test-Path "$tfPath\utilities\base64.c")) {
            Write-Host "Cloning TF-PSA-Crypto..." -ForegroundColor Cyan
            & git clone --depth 1 https://github.com/Mbed-TLS/TF-PSA-Crypto.git $tfPath
        }

        $fwPath = Join-Path $mbedtlsPath "framework"
        if (-not (Test-Path $fwPath) -or (Get-ChildItem -Path $fwPath -Force).Count -eq 0) {
            Write-Host "Cloning Mbed-TLS framework..." -ForegroundColor Cyan
            & git clone --depth 1 https://github.com/Mbed-TLS/mbedtls-framework.git $fwPath
        }
        Write-Host "Submodule staging completed." -ForegroundColor Green
    }
} finally {
    Pop-Location
}
