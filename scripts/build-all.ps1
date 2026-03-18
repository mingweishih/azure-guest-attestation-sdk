#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Unified build script for Azure Guest Attestation SDK with Python support

.DESCRIPTION
    This script extends the main build system to include Python package building.
    It can build Rust core, Python package, or both together.

.PARAMETER Target
    What to build: 'all', 'rust', 'python', 'test' (default: 'all')

.PARAMETER BuildType
    Build type: 'debug' or 'release' (default: 'debug')

.PARAMETER Clean
    Clean build artifacts before building

.PARAMETER Help
    Show help information

.EXAMPLE
    .\build-all.ps1 -Target all -BuildType release -Clean
    
.EXAMPLE
    .\build-all.ps1 -Target python -BuildType debug
#>

param(
    [ValidateSet("all", "rust", "python", "test")]
    [string]$Target = "all",
    
    [ValidateSet("debug", "release")]
    [string]$BuildType = "debug",
    
    [switch]$Clean,
    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

$ErrorActionPreference = "Stop"

# Get script directory and project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "Azure Guest Attestation SDK - Unified Build Script" -ForegroundColor Green
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host "Build Type: $BuildType" -ForegroundColor Yellow
Write-Host "Project Root: $ProjectRoot" -ForegroundColor Yellow

# Available build targets
$targets = @{
    "rust" = @{
        "description" = "Build Rust core library only"
        "script" = "..\python\build.ps1"
        "args" = @("-RustOnly", "-BuildType", $BuildType)
    }
    "python" = @{
        "description" = "Build Python package (includes Rust build)"
        "script" = "..\python\build.ps1" 
        "args" = @("-BuildType", $BuildType)
    }
    "test" = @{
        "description" = "Build and test Python package"
        "script" = "..\python\build.ps1"
        "args" = @("-BuildType", $BuildType)
        "test" = $true
    }
    "all" = @{
        "description" = "Build everything (Rust + Python)"
        "script" = "..\python\build.ps1"
        "args" = @("-BuildType", $BuildType)
    }
}

function Invoke-BuildTarget {
    param(
        [string]$TargetName
    )
    
    $targetInfo = $targets[$TargetName]
    if (-not $targetInfo) {
        throw "Unknown target: $TargetName"
    }
    
    Write-Host "`n=== Building Target: $TargetName ===" -ForegroundColor Cyan
    Write-Host "Description: $($targetInfo.description)" -ForegroundColor Gray
    
    # Prepare arguments
    $scriptArgs = $targetInfo.args
    if ($Clean) {
        $scriptArgs += "-Clean"
    }
    
    # Build the script path
    $scriptPath = Join-Path $ScriptDir $targetInfo.script
    
    if (-not (Test-Path $scriptPath)) {
        throw "Build script not found: $scriptPath"
    }
    
    # Execute the build script
    Write-Host "Executing: $scriptPath $($scriptArgs -join ' ')" -ForegroundColor Gray
    
    try {
        & $scriptPath @scriptArgs
        Write-Host "✓ Target '$TargetName' completed successfully" -ForegroundColor Green
        
        # Run tests if specified
        if ($targetInfo.test) {
            Write-Host "`n=== Running Tests ===" -ForegroundColor Cyan
            $pythonDir = Join-Path $ProjectRoot "python"
            $testScript = Join-Path $pythonDir "test_package.py"
            
            if (Test-Path $testScript) {
                $originalLocation = Get-Location
                try {
                    Set-Location $pythonDir
                    python test_package.py
                    Write-Host "✓ Tests completed" -ForegroundColor Green
                }
                finally {
                    Set-Location $originalLocation
                }
            } else {
                Write-Host "? Test script not found: $testScript" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "✗ Target '$TargetName' failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Show available targets if requested
if ($Target -eq "help") {
    Write-Host "`nAvailable build targets:" -ForegroundColor Cyan
    foreach ($targetName in $targets.Keys | Sort-Object) {
        $targetInfo = $targets[$targetName]
        Write-Host "  $targetName" -ForegroundColor Yellow -NoNewline
        Write-Host " - $($targetInfo.description)" -ForegroundColor Gray
    }
    exit 0
}

# Execute the requested target
try {
    Invoke-BuildTarget $Target
    
    Write-Host "`n=== Build Summary ===" -ForegroundColor Green
    Write-Host "Target: $Target" -ForegroundColor Yellow
    Write-Host "Build Type: $BuildType" -ForegroundColor Yellow
    Write-Host "Status: SUCCESS" -ForegroundColor Green
    
    # Show useful next steps
    Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
    
    if ($Target -in @("python", "all", "test")) {
        $pythonDir = Join-Path $ProjectRoot "python"
        $distDir = Join-Path $pythonDir "dist"
        
        if (Test-Path $distDir) {
            Write-Host "Python package built successfully!" -ForegroundColor Green
            Write-Host "Install locally with:" -ForegroundColor Gray
            Write-Host "  pip install '$distDir\azure_guest_attestation-*.whl'" -ForegroundColor White
            Write-Host "`nOr test with:" -ForegroundColor Gray
            Write-Host "  cd '$pythonDir' && python test_package.py" -ForegroundColor White
        }
    }
    
    if ($Target -in @("rust", "all")) {
        $rustCoreDir = Join-Path $ProjectRoot "rust-core"
        $libPath = Join-Path $rustCoreDir "target\$BuildType\azure_cvm_tpm_sdk.dll"
        
        if (Test-Path $libPath) {
            Write-Host "Rust library built successfully!" -ForegroundColor Green
            Write-Host "Location: $libPath" -ForegroundColor White
        }
    }
}
catch {
    Write-Host "`n=== Build Failed ===" -ForegroundColor Red
    Write-Host "Target: $Target" -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}