# DD FINDER v1.0
# Advanced Threat Detection System
# Developed by valor4.0
# Copyright (c) 2025 Cyber Security Solutions

function Show-Banner {
    Clear-Host
    Write-Host "========================================================================" -ForegroundColor DarkRed
    Write-Host "  ____  ____    _____ ___ _   _ ____  _____ ____  " -ForegroundColor DarkRed
    Write-Host " |  _ \|  _ \  |  ___|_ _| \ | |  _ \| ____|  _ \ " -ForegroundColor DarkRed
    Write-Host " | | | | | | | | |_   | ||  \| | | | |  _| | |_) |" -ForegroundColor Red
    Write-Host " | |_| | |_| | |  _|  | || |\  | |_| | |___|  _ < " -ForegroundColor Red
    Write-Host " |____/|____/  |_|   |___|_| \_|____/|_____|_| \_\" -ForegroundColor DarkRed
    Write-Host "                                                   " -ForegroundColor DarkRed
    Write-Host "========================================================================" -ForegroundColor DarkRed
    Write-Host "                  Advanced Threat Detection System                       " -ForegroundColor Gray
    Write-Host "                  Developed by valor4.0 | v1.0                           " -ForegroundColor Gray
    Write-Host "========================================================================" -ForegroundColor DarkRed
    Write-Host ""
}

function Show-Status {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor Gray
    Write-Host "!" -NoNewline -ForegroundColor Yellow
    Write-Host "] $Message" -ForegroundColor Gray
}

function Show-Success {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor Gray
    Write-Host "+" -NoNewline -ForegroundColor Green
    Write-Host "] $Message" -ForegroundColor Gray
}

function Show-Error {
    param([string]$Message)
    Write-Host "[" -NoNewline -ForegroundColor Gray
    Write-Host "-" -NoNewline -ForegroundColor Red
    Write-Host "] $Message" -ForegroundColor Gray
}

Show-Banner

# Initialize system
Show-Status "Initializing DD FINDER Engine..."
Start-Sleep -Milliseconds 500

# Configuration
$scanPath = "C:\"
$indicators = @(
    "mod_d.class",
    "net/java/a",
    "net/java/c",
    "net/java/b"
)

Show-Status "Loading threat signatures..."
Start-Sleep -Milliseconds 300

# Results collection
$results = @()

Show-Status "Starting system scan..."
Start-Sleep -Milliseconds 200

$ErrorActionPreference = 'SilentlyContinue'

# Scan for JAR files
try {
    Show-Status "Searching for JAR files..."
    $jarFiles = Get-ChildItem -Path $scanPath -Filter "*.jar" -File -Recurse -ErrorAction SilentlyContinue
    
    $totalFiles = $jarFiles.Count
    Write-Progress -Activity "Searching for files" -Status "Found $totalFiles files to scan" -PercentComplete 0
    
    $counter = 0
    foreach ($jarFile in $jarFiles) { 
        $counter++
        $progress = [math]::Round(($counter / $totalFiles) * 100)
        Write-Progress -Activity "Searching for files" -Status "Scanning $($jarFile.Name)" -PercentComplete $progress
        
        try {
            $tempZip = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".zip")
            Copy-Item $jarFile.FullName $tempZip
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)
            
            foreach ($entry in $zip.Entries) {
                foreach ($indicator in $indicators) {
                    if ($entry.FullName -eq $indicator) {
                        $result = [PSCustomObject]@{
                            FileName = $jarFile.FullName
                            IndicatorFound = $indicator
                            DetectionTime = Get-Date
                        }
                        $results += $result
                    }
                }
            }
            $zip.Dispose()
            Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        }
        catch {
            continue
        }
    }
    Write-Progress -Activity "Searching for files" -Completed
}
catch {
    # Silent error handling
}

# Scan for suspicious directories
try {
    Show-Status "Searching for suspicious directories..."
    $cheatDirs = Get-ChildItem -Path $scanPath -Directory -Recurse -ErrorAction SilentlyContinue | 
                 Where-Object { 
                     $dir = $_
                     ($dir.Name -like "*cheat*" -or $dir.Name -like "*hack*" -or $dir.Name -like "*inject*")
                 }
    
    $totalDirs = $cheatDirs.Count
    Write-Progress -Activity "Searching for files" -Status "Found $totalDirs directories to scan" -PercentComplete 0
    
    $counter = 0
    foreach ($cheatDir in $cheatDirs) {
        $counter++
        $progress = [math]::Round(($counter / $totalDirs) * 100)
        Write-Progress -Activity "Searching for files" -Status "Scanning directory $($cheatDir.Name)" -PercentComplete $progress
        
        foreach ($indicator in $indicators) {
            $indicatorPath = Join-Path $cheatDir.FullName $indicator
            if (Test-Path $indicatorPath) {
                $result = [PSCustomObject]@{
                    FileName = $cheatDir.FullName
                    IndicatorFound = $indicator
                    DetectionTime = Get-Date
                }
                $results += $result
            }
        }
    }
    Write-Progress -Activity "Searching for files" -Completed
}
catch {
    # Silent error handling
}

$ErrorActionPreference = 'Continue'

# Export results
if ($results.Count -gt 0) {
    $results | Export-Csv -Path "FullScan.csv" -NoTypeInformation
}

# Final report
Show-Status "Generating threat report..."
Start-Sleep -Milliseconds 500

Show-Success "Results saved to FullScan.csv"
Show-Success "Scan completed!"
