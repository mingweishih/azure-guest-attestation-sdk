#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Clean build artifacts and verify .gitignore is working

.DESCRIPTION
    This script removes all build artifacts and checks that git is properly
    ignoring generated files. Use this to clean up your development environment
    and verify the .gitignore configuration.

.PARAMETER DryRun
    Show what would be cleaned without actually deleting anything

.PARAMETER Verbose
    Show detailed output

.EXAMPLE
    .\clean.ps1
    
.EXAMPLE
    .\clean.ps1 -DryRun -Verbose
#>

param(
    [switch]$DryRun,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "Azure Guest Attestation SDK - Clean Script" -ForegroundColor Green

# Get project root
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Define patterns to clean
$CleanPatterns = @(
    # Rust build artifacts
    "target/",
    "Cargo.lock",
    
    # Python build artifacts  
    "python/build/",
    "python/dist/",
    "python/*.egg-info/",
    "python/__pycache__/",
    "**/__pycache__/",
    "**/*.pyc",
    "**/*.pyo",
    
    # Native libraries
    "**/*.dll",
    "**/*.so", 
    "**/*.dylib",
    "**/*.pdb",
    
    # IDE files
    ".vscode/",
    ".idea/",
    
    # Logs and temp files
    "**/*.log",
    "**/*.tmp",
    "**/*.temp"
)

function Remove-BuildArtifacts {
    param([string[]]$Patterns, [bool]$DryRun, [bool]$Verbose)
    
    $itemsFound = 0
    $itemsRemoved = 0
    
    foreach ($pattern in $Patterns) {
        $fullPattern = Join-Path $ProjectRoot $pattern
        
        if ($Verbose) {
            Write-Host "Checking pattern: $pattern" -ForegroundColor Gray
        }
        
        # Handle directory patterns (ending with /)
        if ($pattern.EndsWith("/")) {
            $dirPattern = $pattern.TrimEnd("/")
            $dirs = Get-ChildItem -Path $ProjectRoot -Recurse -Directory -Name $dirPattern -ErrorAction SilentlyContinue
            
            foreach ($dir in $dirs) {
                $fullPath = Join-Path $ProjectRoot $dir
                if (Test-Path $fullPath) {
                    $itemsFound++
                    Write-Host "Found directory: $dir" -ForegroundColor Yellow
                    
                    if (-not $DryRun) {
                        Remove-Item $fullPath -Recurse -Force
                        Write-Host "  ✓ Removed" -ForegroundColor Green
                        $itemsRemoved++
                    } else {
                        Write-Host "  🔍 Would remove (dry run)" -ForegroundColor Cyan
                    }
                }
            }
        }
        # Handle file patterns
        else {
            $files = Get-ChildItem -Path $ProjectRoot -Recurse -File -Name $pattern -ErrorAction SilentlyContinue
            
            foreach ($file in $files) {
                $fullPath = Join-Path $ProjectRoot $file
                if (Test-Path $fullPath) {
                    $itemsFound++
                    Write-Host "Found file: $file" -ForegroundColor Yellow
                    
                    if (-not $DryRun) {
                        Remove-Item $fullPath -Force
                        Write-Host "  ✓ Removed" -ForegroundColor Green
                        $itemsRemoved++
                    } else {
                        Write-Host "  🔍 Would remove (dry run)" -ForegroundColor Cyan
                    }
                }
            }
        }
    }
    
    return @{
        Found = $itemsFound
        Removed = $itemsRemoved
    }
}

function Test-GitIgnore {
    Write-Host "`n=== Testing .gitignore ===" -ForegroundColor Cyan
    
    # Check if we're in a git repository
    try {
        $null = git rev-parse --git-dir 2>$null
    }
    catch {
        Write-Host "❌ Not in a git repository" -ForegroundColor Red
        return
    }
    
    # Check git status for untracked files that should be ignored
    $gitStatus = git status --porcelain=v1 2>$null
    $untrackedFiles = $gitStatus | Where-Object { $_.StartsWith("??") } | ForEach-Object { $_.Substring(3) }
    
    $problemFiles = @()
    foreach ($file in $untrackedFiles) {
        # Check if this looks like a build artifact
        if ($file -match "\.(dll|so|dylib|pdb|pyc|pyo)$" -or 
            $file -match "(target|build|dist|__pycache__)/" -or
            $file -match "\.egg-info/") {
            $problemFiles += $file
        }
    }
    
    if ($problemFiles.Count -eq 0) {
        Write-Host "✅ .gitignore is working correctly - no build artifacts in git status" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Found untracked build artifacts that should be ignored:" -ForegroundColor Yellow
        foreach ($file in $problemFiles) {
            Write-Host "  - $file" -ForegroundColor Red
        }
        Write-Host "Consider updating .gitignore to ignore these patterns" -ForegroundColor Yellow
    }
}

# Main execution
Write-Host "`n=== Cleaning Build Artifacts ===" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "🔍 DRY RUN MODE - No files will be deleted" -ForegroundColor Yellow
}

$results = Remove-BuildArtifacts -Patterns $CleanPatterns -DryRun $DryRun -Verbose $Verbose

Write-Host "`n=== Clean Summary ===" -ForegroundColor Cyan
Write-Host "Items found: $($results.Found)" -ForegroundColor Yellow

if ($DryRun) {
    Write-Host "Items that would be removed: $($results.Found)" -ForegroundColor Cyan
    Write-Host "Run without -DryRun to actually clean files" -ForegroundColor Gray
} else {
    Write-Host "Items removed: $($results.Removed)" -ForegroundColor Green
}

# Test .gitignore
Test-GitIgnore

Write-Host "`n✅ Clean operation complete!" -ForegroundColor Green