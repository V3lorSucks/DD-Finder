#Requires -Version 5.1

$Script:Config = @{
    MinFileSize = 200KB
    MaxFileSize = 15MB
    ScanTimeout = 300
    DebugMode = $false
    OutputFormat = "Detailed"
}

# Detection Signatures Database
$Script:ThreatSignatures = @{
    BytePatterns = @(
        @{
            Id = "SIG-001"
            Name = "Obfuscated Class Pattern A"
            Bytes = "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800"
            Severity = "High"
        },
        @{
            Id = "SIG-002" 
            Name = "Obfuscated Class Pattern B"
            Bytes = "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16"
            Severity = "High"
        },
        @{
            Id = "SIG-003"
            Name = "Obfuscated Class Pattern C"
            Bytes = "5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3"
            Severity = "Medium"
        }
    )
    
    ClassIndicators = @(
        "net/java/f", "net/java/g", "net/java/h", "net/java/i", "net/java/k",
        "net/java/l", "net/java/m", "net/java/r", "net/java/s", "net/java/t", 
        "net/java/y", "mod_d.class"
    )
    
    SuspiciousExtensions = @(".jar", ".exe", ".dll")
    ExcludedPaths = @("\TEMP\", "\TMP\", "HSPERFDATA", ".tmp")
}

# Performance Monitoring# Performance Monitoring
$Script:PerformanceMetrics = @{
    StartTime = Get-Date
    FilesProcessed = 0
    DetectionsFound = 0
    ScanSpeed = 0
}

# --- Dynamic Terminal Width ---
function Get-TerminalWidth {
    try {
        return $Host.UI.RawUI.WindowSize.Width
    }
    catch {
        
        return 80
    }
}






function Write-TypingEffect {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [int]$Delay = 2
    )
    $Text.ToCharArray() | ForEach-Object {
        Write-Host -NoNewline $_
        Start-Sleep -Milliseconds $Delay
    }
    Write-Host
}

function Write-Banner {
    param (
        [string]$Version = "v2.5",
        [string]$Author = "DrValor (valor4.0)"
    )

    $asciiArt = @"
 _                _ 
   \ \              / / 
    \ \            / / 
     \ \          / / 
      \ \        / / 
       \ \______/ / 
       /          \ 
      /   _    _   \ 
     |   (.)  (.)   | 
     |      /\      | 
      \    '--'    / 
       '----------'
"@
    
    $gradientColors = @("White", "Cyan", "DarkCyan", "Blue", "DarkBlue")

    $width = Get-TerminalWidth
    $borderChar = "="
    $fullBorder = $borderChar * $width

    
    Write-Host $fullBorder -ForegroundColor DarkCyan
    Write-Host

    $lines = $asciiArt.Split([System.Environment]::NewLine)
    foreach ($line in $lines) {
        
        $paddingLength = ($width - $line.Length) / 2
        if ($paddingLength -lt 0) { $paddingLength = 0 }
        $padding = " " * [int]$paddingLength
        Write-Host -NoNewline $padding

        # Render the line character by character with a gradient
        if ($line.Trim().Length -gt 0) {
            $colorStep = $line.Length / $gradientColors.Count
            for ($i = 0; $i -lt $line.Length; $i++) {
                $char = $line[$i]
                $colorIndex = [math]::Min([math]::Floor($i / $colorStep), $gradientColors.Count - 1)
                $charColor = $gradientColors[$colorIndex]
                Write-Host -NoNewline $char -ForegroundColor $charColor
            }
        }
        Write-Host 
    }

    Write-Host

    $infoLine = "Version $Version by $Author"
    $infoPaddingLength = ($width - $infoLine.Length) / 2
    if ($infoPaddingLength -lt 0) { $infoPaddingLength = 0 }
    $infoPadding = " " * [int]$infoPaddingLength
    Write-Host -NoNewline $infoPadding
    Write-Host $infoLine -ForegroundColor DarkGray
    
    Write-Host

    Write-Host $fullBorder -ForegroundColor DarkCyan
    Write-Host
}



function Write-Section {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title
    )
    $width = Get-TerminalWidth
    $paddingLength = ($width - $Title.Length - 2) / 2
    $padding = "-" * [int]$paddingLength
    $formattedTitle = "$padding $($Title.ToUpper()) $padding"
    if ($formattedTitle.Length -gt $width) {
        $formattedTitle = "$($padding) $($Title.ToUpper()) $($padding)-"
    }
    Write-Host $formattedTitle -ForegroundColor White
    Write-Host
}

function Write-Info {
    param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)] [string]$Message)
    process { Write-Host "[*] $Message" -ForegroundColor Cyan }
}

function Write-Success {
    param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)] [string]$Message)
    process { Write-Host "[+] $Message" -ForegroundColor Green }
}

function Write-Warning {
    param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)] [string]$Message)
    process { Write-Host "[!] $Message" -ForegroundColor Yellow }
}

function Write-Error {
    param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)] [string]$Message)
    process { Write-Host "[-] $Message" -ForegroundColor Red }
}

function Write-System {
    param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)] [string]$Message)
    process { Write-Host "[SYSTEM] $Message" -ForegroundColor DarkGray }
}





function Show-MainMenu {
    Clear-Host
    Write-Banner

    Write-Host "   [1] Start Scan" -ForegroundColor Cyan
    Write-Host "   [2] View Last Results" -ForegroundColor Cyan
    Write-Host "   [3] Export Report" -ForegroundColor Cyan
    Write-Host "   [4] Exit" -ForegroundColor Cyan
    Write-Host

    $choice = Read-Host -Prompt ">> Select an option"

    return $choice
}





$Global:Spinner = (
    "|",
    "/",
    "-",
    "\"
)

function Start-Spinner {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $spinnerThread = [PowerShell]::Create().AddScript({
        param ($Message, $Spinner)

        $i = 0
        while ($true) {
            $frame = $Spinner[$i % $Spinner.Count]
            Write-Host -NoNewline "`r$frame $Message..."
            $i++
            Start-Sleep -Milliseconds 100
        }
    })
    $spinnerThread.AddParameters(@($Message, $Global:Spinner)) | Out-Null
    $spinnerThread.BeginInvoke() | Out-Null
    return $spinnerThread
}

function Stop-Spinner {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PowerShell]$SpinnerThread,
        [bool]$Success = $true,
        [string]$ResultMessage = "Done"
    )
    $SpinnerThread.Stop()
    $SpinnerThread.Dispose()
    if ($Success) { Write-Host -NoNewline "[V]" -ForegroundColor Green } else { Write-Host -NoNewline "[X]" -ForegroundColor Red }
    Write-Host " $ResultMessage      "
}

function Write-ScanProgress {
    param (
        [Parameter(Mandatory = $true)]
        [int]$CurrentValue,
        [Parameter(Mandatory = $true)]
        [int]$TotalValue
    )
    $width = (Get-TerminalWidth) - 40 # Adjust width for text
    $percentage = if ($TotalValue -gt 0) { [math]::Round(($CurrentValue / $TotalValue) * 100) } else { 0 }
    $progressChars = [int]($percentage / 100 * $width)
    $progressBar = ("#" * $progressChars) + ("-" * ($width - $progressChars))

    $progressText = "[$progressBar] $($percentage)% ($CurrentValue/$TotalValue)"
    Write-Host -NoNewline ("`r" + $progressText)
}

# --- Table and Summary Functions ---

function Write-Table {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data,
        [string[]]$Headers
    )

    if ($Data.Count -eq 0) {
        Write-Info "No items to display in the table."
        return
    }

    # If no headers are provided, use the properties of the first object
    if (-not $Headers) {
        $Headers = $Data[0].PSObject.Properties.Name
    }

    # Calculate column widths
    $widths = @{}
    foreach ($header in $Headers) {
        $maxWidth = $header.Length
        foreach ($row in $Data) {
            $value = "$($row.$header)"
            if ($value.Length -gt $maxWidth) {
                $maxWidth = $value.Length
            }
        }
        $widths[$header] = $maxWidth
    }

    # --- Draw Table ---
    $line = ''
    $headerLine = ''
    foreach ($header in $Headers) {
        $width = $widths[$header]
        $line += '-' * ($width + 2) + '+'
        $headerLine += " $($header.PadRight($width)) |"
    }
    $line = '+' + $line.TrimEnd('+') + '+'
    $headerLine = '|' + $headerLine.TrimEnd('|') + '|'
    $separator = $line -replace '\+', '|'

    Write-Host $line -ForegroundColor White
    Write-Host $headerLine -ForegroundColor White
    Write-Host $separator -ForegroundColor White

    foreach ($row in $Data) {
        $rowLine = ''
        foreach ($header in $Headers) {
            $width = $widths[$header]
            $value = "$($row.$header)".PadRight($width)
            $rowLine += " $value |"
        }
        Write-Host ('|' + $rowLine.TrimEnd('|') + '|') -ForegroundColor White
    }

    $footer = $line
    Write-Host $footer -ForegroundColor White
}

function Write-Summary {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$SummaryData
    )
    Write-Section -Title "SCAN COMPLETE"
    foreach ($key in $SummaryData.Keys) {
        $value = $SummaryData[$key]
        $label = "$($key.PadRight(15))"
        Write-Host -NoNewline " ${label}: " -ForegroundColor White
        Write-Host $value
    }
    Write-Host
}

#endregion ADVANCED UI

#region CORE LOGIC

# Main Framework Class
class SecurityScanner {
    [string]$Name
    [hashtable]$Configuration
    [array]$DetectionResults
    
    SecurityScanner([string]$scannerName, [hashtable]$config) {
        $this.Name = $scannerName
        $this.Configuration = $config
        $this.DetectionResults = @()
    }
    
    [void] LogEvent([string]$message, [string]$level = "INFO") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$level] $message"
        
        switch ($level.ToUpper()) {
            "ERROR" { Write-Error $logEntry }
            "WARNING" { Write-Warning $logEntry }
            "SUCCESS" { Write-Success $logEntry }
            default { Write-Info $logEntry }
        }
    }
    
    [array] GetResults() {
        return $this.DetectionResults
    }
}

# Initialize Framework
function Initialize-Framework {
    param([hashtable]$config)
    
    $scanner = [SecurityScanner]::new("Enterprise Threat Detector", $config)
    $scanner.LogEvent("Framework initialized successfully", "SUCCESS")
    return $scanner
}

# System Privilege Verification
function Test-SystemPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Environment Analysis
function Get-SystemEnvironment {
    $envInfo = [PSCustomObject]@{
        OSVersion = [System.Environment]::OSVersion.Version
        Architecture = [System.Environment]::Is64BitOperatingSystem
        Processors = [System.Environment]::ProcessorCount
        AvailableMemory = (Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory / 1MB
        SystemDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    }
    
    return $envInfo
}

# File System Intelligence Gathering
function Get-FileSystemIntelligence {
    param([string[]]$driveLetters)
    
    $intelligence = @{
        RecentActivity = @{}
        DeletedFiles = @()
        SuspiciousPaths = @()
    }
    
    foreach ($drive in $driveLetters) {
        try {
            # Monitor recent file operations via event logs
            $recentEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4663, 4656, 4660
                StartTime = (Get-Date).AddHours(-24)
            } -ErrorAction SilentlyContinue | Select-Object -First 100
            
            # Analyze prefetch data
            $prefetchPath = "C:\Windows\Prefetch"
            if (Test-Path $prefetchPath) {
                $javaPrefetch = Get-ChildItem -Path $prefetchPath -Filter "JAVA*.pf" -ErrorAction SilentlyContinue
                foreach ($pf in $javaPrefetch) {
                    # Extract referenced files (simplified)
                    $referencedFiles = Extract-PrefetchReferences -FilePath $pf.FullName
                    $intelligence.SuspiciousPaths += $referencedFiles
                }
            }
            
        } catch {
            # Continue silently on access issues
        }
    }
    
    return $intelligence
}

# Prefetch Data Extraction (Placeholder - would need actual implementation)
function Extract-PrefetchReferences {
    param([string]$FilePath)
    
    # This would contain actual prefetch parsing logic
    # For now, returning placeholder data
    return @()
}

# Advanced File Analysis Engine
function Invoke-AdvancedFileAnalysis {
    param(
        [string]$filePath,
        [SecurityScanner]$scanner
    )
    
    $analysisResult = [PSCustomObject]@{
        FilePath = $filePath
        IsMalicious = $false
        ConfidenceLevel = "None"
        DetectionDetails = @()
        FileMetrics = @{}
        ThreatScore = 0
    }
    
    try {
        # File validation
        if (-not (Test-Path $filePath -PathType Leaf)) {
            return $analysisResult
        }
        
        $fileInfo = Get-Item $filePath -ErrorAction Stop
        $analysisResult.FileMetrics.Size = $fileInfo.Length
        $analysisResult.FileMetrics.Extension = $fileInfo.Extension.ToLower()
        
        # Size validation
        if ($fileInfo.Length -lt $Script:Config.MinFileSize -or 
            $fileInfo.Length -gt $Script:Config.MaxFileSize) {
            return $analysisResult
        }
        
        # Magic byte verification
        if ($analysisResult.FileMetrics.Extension -eq ".jar") {
            $isJar = Test-JarSignature -Path $filePath
            if (-not $isJar) {
                return $analysisResult
            }
            
            # Comprehensive JAR analysis
            $jarAnalysis = Analyze-JarContent -Path $filePath -Scanner $scanner
            $analysisResult.DetectionDetails += $jarAnalysis.Details
            $analysisResult.ThreatScore += $jarAnalysis.Score
            
            if ($jarAnalysis.Score -gt 50) {
                $analysisResult.IsMalicious = $true
                $analysisResult.ConfidenceLevel = "High"
            } elseif ($jarAnalysis.Score -gt 25) {
                $analysisResult.IsMalicious = $true
                $analysisResult.ConfidenceLevel = "Medium"
            } elseif ($jarAnalysis.Score -gt 10) {
                $analysisResult.IsMalicious = $true
                $analysisResult.ConfidenceLevel = "Low"
            }
        }
        
    } catch {
        $scanner.LogEvent("Analysis error for $filePath : $($_.Exception.Message)", "ERROR")
    }
    
    return $analysisResult
}

# JAR Signature Validation
function Test-JarSignature {
    param([string]$Path)
    
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $reader = New-Object System.IO.BinaryReader($stream)
        
        if ($stream.Length -lt 4) {
            $reader.Close()
            $stream.Close()
            return $false
        }
        
        $magic1 = $reader.ReadByte()
        $magic2 = $reader.ReadByte()
        $magic3 = $reader.ReadByte()
        $magic4 = $reader.ReadByte()
        
        $reader.Close()
        $stream.Close()
        
        # ZIP magic bytes: 50 4B 03 04
        return ($magic1 -eq 0x50 -and $magic2 -eq 0x4B -and $magic3 -eq 0x03 -and $magic4 -eq 0x04)
        
    } catch {
        return $false
    }
}

# Deep JAR Content Analysis
function Analyze-JarContent {
    param(
        [string]$Path,
        [SecurityScanner]$Scanner
    )
    
    $analysis = @{
        Details = @()
        Score = 0
        ClassCount = 0
        SuspiciousClasses = @()
    }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $classEntries = $jar.Entries | Where-Object { $_.FullName -like "*.class" }
        $analysis.ClassCount = $classEntries.Count
        
        # Early exit for legitimate libraries
        if ($analysis.ClassCount -gt 50) {
            $jar.Dispose()
            return $analysis
        }
        
        # Extract and analyze class data
        $allClassData = @()
        foreach ($entry in $classEntries) {
            $stream = $entry.Open()
            $data = New-Object byte[] $entry.Length
            $stream.Read($data, 0, $data.Length) | Out-Null
            $allClassData += $data
            $stream.Close()
        }
        
        $jar.Dispose()
        
        # Byte pattern matching
        foreach ($pattern in $Script:ThreatSignatures.BytePatterns) {
            $patternBytes = Convert-HexToBytes -HexString $pattern.Bytes
            if (Find-BytePattern -Data $allClassData -Pattern $patternBytes) {
                $analysis.Details += "Matched signature: $($pattern.Name)"
                $analysis.Score += switch ($pattern.Severity) {
                    "High" { 30 }
                    "Medium" { 15 }
                    "Low" { 5 }
                }
            }
        }
        
        # Class name analysis
        foreach ($indicator in $Script:ThreatSignatures.ClassIndicators) {
            if (Find-ClassIndicator -Data $allClassData -ClassName $indicator) {
                $analysis.Details += "Found suspicious class: $indicator"
                $analysis.Score += 8
                $analysis.SuspiciousClasses += $indicator
            }
        }
        
        # Single letter class detection
        $singleLetterClasses = Find-SingleLetterClasses -Path $Path
        if ($singleLetterClasses.Count -gt 0) {
            $analysis.Details += "Single-letter classes detected: $($singleLetterClasses.Count)"
            $analysis.Score += [Math]::Min($singleLetterClasses.Count * 3, 20)
        }
        
    } catch {
        $Scanner.LogEvent("JAR analysis failed: $($_.Exception.Message)", "ERROR")
    }
    
    return $analysis
}

# Utility Functions
function Convert-HexToBytes {
    param([string]$HexString)
    
    $bytes = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Find-BytePattern {
    param([byte[]]$Data, [byte[]]$Pattern)
    
    $patternLength = $Pattern.Length
    $dataLength = $Data.Length
    
    for ($i = 0; $i -le ($dataLength - $patternLength); $i++) {
        $match = $true
        for ($j = 0; $j -lt $patternLength; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) { return $true }
    }
    return $false
}

function Find-ClassIndicator {
    param([byte[]]$Data, [string]$ClassName)
    
    $classBytes = [System.Text.Encoding]::ASCII.GetBytes($ClassName)
    return Find-BytePattern -Data $Data -Pattern $classBytes
}

function Find-SingleLetterClasses {
    param([string]$Path)
    
    $singleLetters = @()
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        foreach ($entry in $jar.Entries) {
            if ($entry.FullName -like "*.class") {
                $className = [System.IO.Path]::GetFileNameWithoutExtension($entry.FullName)
                if ($className -match '^[a-zA-Z]$') {
                    $singleLetters += $entry.FullName
                }
            }
        }
        $jar.Dispose()
    } catch {}
    
    return $singleLetters
}

# Cross-Drive File Resolution
function Resolve-FileLocations {
    param([array]$paths, [array]$availableDrives)
    
    $resolvedFiles = @{}
    $missingFiles = @()
    
    foreach ($path in $paths) {
        $found = $false
        
        # Check original path
        if (Test-Path $path -PathType Leaf) {
            $resolvedFiles[$path] = $path
            $found = $true
            continue
        }
        
        # Try alternative drives
        if ($path -match '^([A-Z]):\\(.*)$') {
            $relativePath = $Matches[2]
            
            foreach ($drive in $availableDrives) {
                $testPath = "$drive`:\$relativePath"
                if (Test-Path $testPath -PathType Leaf) {
                    $resolvedFiles[$path] = $testPath
                    $found = $true
                    break
                }
            }
        }
        
        if (-not $found) {
            $missingFiles += $path
        }
    }
    
    return @{
        Resolved = $resolvedFiles
        Missing = $missingFiles
    }
}

# Enhanced Reporting Engine
function Generate-EnhancedReport {
    param(
        [array]$detections,
        [hashtable]$metrics,
        [object]$environment
    )
    
    $report = [ordered]@{
        ScanMetadata = @{
            Timestamp = Get-Date
            Duration = (Get-Date) - $Script:PerformanceMetrics.StartTime
            FrameworkVersion = "2.0 Enterprise"
        }
        
        EnvironmentInfo = @{
            OperatingSystem = "Windows $($environment.OSVersion.Major).$($environment.OSVersion.Minor)"
            Architecture = if ($environment.Architecture) { "64-bit" } else { "32-bit" }
            Processors = $environment.Processors
            MemoryAvailable = "$([Math]::Round($environment.AvailableMemory, 2)) MB"
        }
        
        ScanResults = @{
            TotalFilesAnalyzed = $metrics.FilesProcessed
            DetectionsFound = $detections.Count
            DetectionRate = if ($metrics.FilesProcessed -gt 0) { 
                "$([Math]::Round(($detections.Count / $metrics.FilesProcessed) * 100, 2))%" 
            } else { "0%" }
        }
        
        DetailedDetections = $detections
    }
    
    return $report
}

# Main Execution Pipeline
function Start-ProfessionalScan {
    param([switch]$Debug)
    
    # Set debug mode
    $Script:Config.DebugMode = $Debug
    
    # Initialize framework
    $scanner = Initialize-Framework -config $Script:Config
    
    # Verify privileges
    if (-not (Test-SystemPrivileges)) {
        $scanner.LogEvent("Administrative privileges required for comprehensive scanning", "ERROR")
        return
    }
    
    # Analyze environment
    $environment = Get-SystemEnvironment
    $scanner.LogEvent("System environment analyzed successfully", "SUCCESS")
    
    # Identify available drives
    $ntfsDrives = $environment.SystemDrives | Where-Object { 
        try { (Get-Volume -DriveLetter $_.Root[0] -ErrorAction SilentlyContinue).FileSystem -eq 'NTFS' }
        catch { $false }
    } | ForEach-Object { $_.Root[0] }
    
    $scanner.LogEvent("Identified $($ntfsDrives.Count) NTFS drives for analysis", "INFO")
    
    # Gather intelligence
    $intelligence = Get-FileSystemIntelligence -driveLetters $ntfsDrives
    
    # Discover target files
    $targetFiles = @()
    
    # Method 1: Prefetch analysis
    $targetFiles += $intelligence.SuspiciousPaths
    
    # Method 2: Direct filesystem scan
    foreach ($drive in $ntfsDrives) {
        try {
            $jarFiles = Get-ChildItem -Path "$drive`:\" -Filter "*.jar" -Recurse -ErrorAction SilentlyContinue |
                       Where-Object { 
                           $_.Length -ge $Script:Config.MinFileSize -and 
                           $_.Length -le $Script:Config.MaxFileSize
                       }
            $targetFiles += $jarFiles.FullName
        } catch {}
    }
    
    # Remove duplicates and resolve locations
    $uniqueFiles = $targetFiles | Select-Object -Unique
    $resolution = Resolve-FileLocations -paths $uniqueFiles -availableDrives $ntfsDrives
    
    $scanner.LogEvent("Located $($resolution.Resolved.Count) files for analysis", "SUCCESS")
    $scanner.LogEvent("$($resolution.Missing.Count) files could not be located", "WARNING")
    
    # Perform detailed analysis
    $detections = @()
    $fileCounter = 0
    $totalFiles = $resolution.Resolved.Count
    
    foreach ($originalPath in $resolution.Resolved.Keys) {
        $actualPath = $resolution.Resolved[$originalPath]
        $fileCounter++
        
        # Progress indication
        Write-ScanProgress -CurrentValue $fileCounter -TotalValue $totalFiles
        
        $result = Invoke-AdvancedFileAnalysis -filePath $actualPath -scanner $scanner
        $Script:PerformanceMetrics.FilesProcessed++
        
        if ($result.IsMalicious) {
            $detections += [PSCustomObject]@{
                FilePath = $actualPath
                OriginalReference = $originalPath
                Confidence = $result.ConfidenceLevel
                ThreatScore = $result.ThreatScore
                Details = $result.DetectionDetails -join "; "
            }
            $Script:PerformanceMetrics.DetectionsFound++
        }
    }
    
    # Generate comprehensive report
    $finalReport = Generate-EnhancedReport -detections $detections -metrics $Script:PerformanceMetrics -environment $environment
    
    # Display results
    Display-ProfessionalResults -report $finalReport -scanner $scanner
    
    return $finalReport
}

# Professional Results Presentation
function Display-ProfessionalResults {
    param([hashtable]$report, [SecurityScanner]$scanner)
    
    Write-Section -Title "SCAN EXECUTION SUMMARY"
    
    $summary = [
        ordered] @{
        'Execution Time' = $report.ScanMetadata.Duration.ToString("hh\:mm\:ss")
        'Files Analyzed' = $report.ScanResults.TotalFilesAnalyzed
        'Detections Found' = $report.ScanResults.DetectionsFound
        'Detection Rate' = $report.ScanResults.DetectionRate
    }
    Write-Summary -SummaryData $summary

    Write-Section -Title "SYSTEM ENVIRONMENT"
    $envSummary = [
        ordered] @{
        'OS' = $report.EnvironmentInfo.OperatingSystem
        'Architecture' = $report.EnvironmentInfo.Architecture
        'Processors' = $report.EnvironmentInfo.Processors
        'Memory Available' = $report.EnvironmentInfo.MemoryAvailable
    }
    Write-Summary -SummaryData $envSummary
    
    # Detailed Detections
    if ($report.DetailedDetections.Count -gt 0) {
        Write-Section -Title "DETECTION SUMMARY"
        
        $results = @()
        foreach($detection in $report.DetailedDetections){
            $results += [pscustomobject]@{
                ID = $results.Count + 1
                File = $detection.FilePath
                Confidence = $detection.Confidence
                Score = $detection.ThreatScore
                Details = $detection.Details
            }
        }
        Write-Table -Data $results -Headers 'ID', 'File', 'Confidence', 'Score', 'Details'
        
        Write-Warning "Recommended Action: Review flagged files and apply security policies."
        
    } else {
        Write-Success "SCAN RESULT: NO THREATS DETECTED"
    }
    
    Write-System "Scan completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

# 2ND.PS1 FUNCTIONALITY MOVED TO TOP

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Global debug flag
$script:DebugMode = $false
$script:CheckUSN = $true
$Script:QuietMode = $false

# Cache for USN journal data
$script:RecentDeletions = @{}
$script:USNSearched = $false

function Get-NTFSDrives {
    $ntfsDrives = @()
    
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    
    foreach ($drive in $drives) {
        try {
            $driveLetter = $drive.Root.Substring(0, 2)
            
            # Check if drive is NTFS
            $volume = Get-Volume -DriveLetter $driveLetter[0] -ErrorAction SilentlyContinue

            if ($volume -and $volume.FileSystem -eq 'NTFS') {
                $ntfsDrives += $driveLetter[0]
            }
        }
        catch {
            # Skip drives that can't be accessed
            continue
        }
    }
    
    return $ntfsDrives
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NtdllDecompressor {
    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat,
        byte[] UncompressedBuffer,
        int UncompressedBufferSize,
        byte[] CompressedBuffer,
        int CompressedBufferSize,
        out int FinalUncompressedSize,
        IntPtr WorkSpace
    );
    
    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormat,
        out uint CompressBufferWorkSpaceSize,
        out uint CompressFragmentWorkSpaceSize
    );
    
    public static byte[] Decompress(byte[] compressed) {
        if (compressed.Length < 8) return null;
        if (compressed[0] != 0x4D || compressed[1] != 0x41 || compressed[2] != 0x4D) {
            return null;
        }
        
        int uncompSize = BitConverter.ToInt32(compressed, 4);
        
        uint wsComp, wsFrag;
        if (RtlGetCompressionWorkSpaceSize(4, out wsComp, out wsFrag) != 0) return null;
        
        IntPtr workspace = Marshal.AllocHGlobal((int)wsFrag);
        byte[] result = new byte[uncompSize];
        
        try {
            int finalSize;
            byte[] compData = new byte[compressed.Length - 8];
            Array.Copy(compressed, 8, compData, 0, compData.Length);
            
            uint status = RtlDecompressBufferEx(4, result, uncompSize, 
                compData, compData.Length, out finalSize, workspace);
            
            if (status != 0) return null;
            return result;
        }
        finally {
            Marshal.FreeHGlobal(workspace);
        }
    }
}
"@

function Get-RecentDeletionsFromUSN {
    param(
        [string[]]$DriveLetters,
        [int]$MinutesBack = 30
    )
    
    if ($script:USNSearched) {
        return $script:RecentDeletions
    }
    
    $allRecentActivity = @{}
    
    foreach ($driveLetter in $DriveLetters) {
        try {
            if (-not $Script:QuietMode) { Write-Info "Scanning drive $driveLetter`: for recent file activity (last $MinutesBack minutes)..." }
            
            $cutoffTime = (Get-Date).AddMinutes(-$MinutesBack)
            
            # Run fsutil to get USN journal
            $usnOutput = & fsutil usn readjournal "$driveLetter`:" 2>$null
            
            if ($LASTEXITCODE -ne 0) {
                if (-not $Script:QuietMode) { Write-Warning "Unable to read USN Journal on drive $driveLetter`: (may be disabled)" }
                continue
            }
            
            $totalLines = $usnOutput.Count
            
            if ($totalLines -eq 0) {
                if (-not $Script:QuietMode) { Write-Warning "No USN Journal data on drive $driveLetter`:" }
                continue
            }
            
            $recentActivity = @{}
            $activityCount = 0
            $currentFile = ""
            $currentTime = $null
            $currentReason = ""
            $entriesProcessed = 0
            
            foreach ($line in $usnOutput) {
                # Skip empty lines
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                
                # Look for "File name" line (with variable spacing)
                if ($line -match 'File name\s+:\s+(.+)$') {
                    $currentFile = $Matches[1].Trim()
                }
                # Look for "Time stamp" line (with variable spacing)
                elseif ($line -match 'Time stamp\s+:\s+(.+)$') {
                    $timeStr = $Matches[1].Trim()
                    try {
                        $currentTime = [DateTime]::Parse($timeStr)
                    } catch {
                        $currentTime = $null
                    }
                }
                # Look for "Reason" line - accept ANY reason
                elseif ($line -match 'Reason\s+:\s+(.+)$') {
                    $entriesProcessed++
                    $currentReason = $Matches[1].Trim()
                    
                    # Check if this entry is within our time window (ANY reason)
                    if ($currentFile -and $currentTime -and $currentTime -gt $cutoffTime) {
                        # Store with drive letter prefix to avoid collisions
                        $fullKey = "$driveLetter`:\$currentFile"
                        
                        # If file appears multiple times, keep the most recent
                        if (-not $recentActivity.ContainsKey($fullKey) -or 
                            $recentActivity[$fullKey].Timestamp -lt $currentTime) {
                            
                            $recentActivity[$fullKey] = @{
                                Timestamp = $currentTime
                                Reason = $currentReason
                                Drive = $driveLetter
                            }
                            
                            $activityCount++
                        }
                    }
                    
                    # Reset for next entry
                    $currentFile = ""
                    $currentTime = $null
                    $currentReason = ""
                }
            }
            
            if (-not $Script:QuietMode) { Write-Success "Drive $driveLetter`: - Found $activityCount files with recent activity" }
            
            # Merge into overall activity
            foreach ($key in $recentActivity.Keys) {
                $allRecentActivity[$key] = $recentActivity[$key]
            }
            
        }
        catch {
            if (-not $Script:QuietMode) { Write-Warning "Error reading USN Journal on drive $driveLetter`: - $_" }
            continue
        }
    }
    
    $script:RecentDeletions = $allRecentActivity
    $script:USNSearched = $true
    
    if (-not $Script:QuietMode) {
        Write-Host ""
        Write-Success "Total unique files with recent activity across all drives: $($allRecentActivity.Count)"
        Write-Host ""
    }
    
    return $allRecentActivity
}

function Test-RecentlyDeleted {
    param(
        [string]$FilePath
    )
    
    # Try full path match first
    if ($script:RecentDeletions.ContainsKey($FilePath)) {
        return $script:RecentDeletions[$FilePath]
    }
    
    # Try just filename
    $fileName = [System.IO.Path]::GetFileName($FilePath)
    
    # Check if any key ends with this filename
    foreach ($key in $script:RecentDeletions.Keys) {
        if ($key -like "*$fileName") {
            return $script:RecentDeletions[$key]
        }
    }
    
    return $null
}

function Get-PrefetchVersion {
    param([byte[]]$data)
    
    if ($data.Length -lt 8) { return 0 }
    
    # Check for SCCA signature at offset 4
    $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
    if ($sig -ne "SCCA") { return 0 }
    
    # Version is at offset 0
    $version = [BitConverter]::ToUInt32($data, 0)
    return $version
}

function Get-SystemIndexes {
    param([string]$FilePath)
    
    try {
        $data = [System.IO.File]::ReadAllBytes($FilePath)
        
        if ($script:DebugMode) {
            Write-Info "  [DEBUG] File: $([System.IO.Path]::GetFileName($FilePath))"
            Write-Info "  [DEBUG] Raw size: $($data.Length) bytes"
        }
        
        $isCompressed = ($data[0] -eq 0x4D -and $data[1] -eq 0x41 -and $data[2] -eq 0x4D)
        
        if ($script:DebugMode) {
            Write-Info "  [DEBUG] Compressed: $isCompressed"
        }
        
        if ($isCompressed) {
            $data = [NtdllDecompressor]::Decompress($data)
            if ($data -eq $null) {
                Write-Warning "Failed to decompress: $FilePath"
                return @()
            }
            
            if ($script:DebugMode) {
                Write-Info "  [DEBUG] Decompressed size: $($data.Length) bytes"
            }
        }
        
        # Validate minimum size
        if ($data.Length -lt 108) {
            Write-Warning "File too small after decompression: $FilePath"
            return @()
        }
        
        # Get prefetch version
        $version = Get-PrefetchVersion -data $data
        
        if ($script:DebugMode) {
            Write-Info "  [DEBUG] Prefetch version: $version"
        }
        
        $sig = [System.Text.Encoding]::ASCII.GetString($data, 4, 4)
        if ($sig -ne "SCCA") {
            Write-Warning "Invalid file signature: $FilePath (got: $sig)"
            return @()
        }
        
        # Handle different prefetch versions
        # Version 17 = XP/2003, 23 = Vista/7, 26 = Win8.1, 30 = Win10, 31 = Win11
        $stringsOffset = 0
        $stringsSize = 0
        
        switch ($version) {
            17 {
                # Windows XP/2003
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            23 {
                # Windows Vista/7
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            26 {
                # Windows 8.1
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            30 {
                # Windows 10
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            31 {
                # Windows 11
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
            default {
                Write-Warning "Unknown prefetch version $version for: $FilePath"
                # Try default offsets anyway
                $stringsOffset = [BitConverter]::ToUInt32($data, 100)
                $stringsSize = [BitConverter]::ToUInt32($data, 104)
            }
        }
        
        if ($script:DebugMode) {
            Write-Info "  [DEBUG] Strings offset: $stringsOffset"
            Write-Info "  [DEBUG] Strings size: $stringsSize"
        }
        
        # Validate offsets
        if ($stringsOffset -eq 0 -or $stringsSize -eq 0) {
            Write-Warning "Invalid string section offsets: $FilePath"
            return @()
        }
        
        if ($stringsOffset -ge $data.Length -or ($stringsOffset + $stringsSize) -gt $data.Length) {
            Write-Warning "String section out of bounds: $FilePath (offset: $stringsOffset, size: $stringsSize, data: $($data.Length))"
            return @()
        }
        
        $filenames = @()
        $pos = $stringsOffset
        $endPos = $stringsOffset + $stringsSize
        
        while ($pos -lt $endPos -and $pos -lt $data.Length - 2) {
            $nullPos = $pos
            while ($nullPos -lt $data.Length - 1) {
                if ($data[$nullPos] -eq 0 -and $data[$nullPos + 1] -eq 0) {
                    break
                }
                $nullPos += 2
            }
            
            if ($nullPos -gt $pos) {
                $strLen = $nullPos - $pos
                if ($strLen -gt 0 -and $strLen -lt 2048) {
                    try {
                        $filename = [System.Text.Encoding]::Unicode.GetString($data, $pos, $strLen)
                        if ($filename.Length -gt 0) {
                            $filenames += $filename
                        }
                    }
                    catch { }
                }
            }
            
            $pos = $nullPos + 2
            
            if ($filenames.Count -gt 1000) { break }
        }
        
        if ($script:DebugMode) {
            Write-Info "  [DEBUG] Extracted $($filenames.Count) filenames"
        }
        
        return $filenames
    }
    catch {
        Write-Warning "Error parsing $FilePath : $_"
        if ($script:DebugMode) {
            Write-Error "  [DEBUG] Exception: $($_.Exception.GetType().Name)"
            Write-Error "  [DEBUG] Message: $($_.Exception.Message)"
        }
        return @()
    }
}

function Test-FileInSizeRange {
    param(
        [string]$Path,
        [long]$MinBytes = 200KB,
        [long]$MaxBytes = 15MB
    )
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        return $false
    }
    
    try {
        $size = (Get-Item $Path -ErrorAction Stop).Length
        return ($size -ge $MinBytes -and $size -le $MaxBytes)
    }
    catch {
        return $false
    }
}

$script:BytePatterns = @(
    @{ 
        Name = "Pattern #1" 
        Bytes = "6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A160C14005C6588B800"
    },
    @{ 
        Name = "Pattern #2" 
        Bytes = "0C1504851D85160A6161370E160609949E0029033EA7000A2C1D03548403011D1008A1FFF6033EA7000A2B1D03548403011D07A1FFF710FEAC150599001A2A16"
    },
    @{ 
        Name = "Pattern #3" 
        Bytes = "5910071088544C2A2BB8004D3B033DA7000A2B1C03548402011C1008A1FFF61A9E000C1A110800A2000503AC04AC00000000000A0005004E000101FA000001D3"
    }
)

$script:ClassPatterns = @(
    "net/java/f",
    "net/java/g",
    "net/java/h",
    "net/java/i",
    "net/java/k",
    "net/java/l",
    "net/java/m",
    "net/java/r",
    "net/java/s",
    "net/java/t",
    "net/java/y"
)

function ConvertHex-ToBytes {
    param([string]$hexString)
    
    $bytes = New-Object byte[] ($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Search-BytePattern {
    param(
        [byte[]]$data,
        [byte[]]$pattern
    )
    
    $patternLength = $pattern.Length
    $dataLength = $data.Length
    
    for ($i = 0; $i -le ($dataLength - $patternLength); $i++) {
        $match = $true
        for ($j = 0; $j -lt $patternLength; $j++) {
            if ($data[$i + $j] -ne $pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $true
        }
    }
    return $false
}

function Search-ClassPattern {
    param(
        [byte[]]$data,
        [string]$className
    )
    
    $classBytes = [System.Text.Encoding]::ASCII.GetBytes($className)
    return Search-BytePattern -data $data -pattern $classBytes
}

function Test-ZipMagicBytes {
    param([string]$Path)
    
    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $reader = New-Object System.IO.BinaryReader($fileStream)
        
        if ($fileStream.Length -lt 2) {
            $reader.Close()
            $fileStream.Close()
            return $false
        }
        
        $byte1 = $reader.ReadByte()
        $byte2 = $reader.ReadByte()
        
        $reader.Close()
        $fileStream.Close()
        
        return ($byte1 -eq 0x50 -and $byte2 -eq 0x4B)
        
    } catch {
        return $false
    }
}

function Find-SingleLetterClasses {
    param([string]$Path)
    
    $singleLetterClasses = @()
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        foreach ($entry in $jar.Entries) {
            if ($entry.FullName -like "*.class") {
                $className = $entry.FullName
                
                $parts = $className -split '/'
                $filename = $parts[-1]
                
                $classNameOnly = $filename -replace '\.class$', ''
                
                if ($classNameOnly -match '^[a-zA-Z]$') {
                    $fullPath = ($parts[0..($parts.Length-2)] -join '/') + '/' + $classNameOnly
                    $singleLetterClasses += $fullPath
                }
            }
        }
        
        $jar.Dispose()
        
    } catch {
    }
    
    return $singleLetterClasses
}

function Test-DoomsdayClient {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    $result = [PSCustomObject]@{
        IsDetected = $false
        Confidence = "NONE"
        BytePatternMatches = @()
        ClassNameMatches = @()
        SingleLetterClasses = @()
        IsRenamedJar = $false
        Error = $null
    }
    
    if (-not (Test-Path $Path -PathType Leaf)) {
        $result.Error = "File not found"
        return $result
    }
    
    try {
        $fileExtension = [System.IO.Path]::GetExtension($Path).ToLower()
        
        $hasPKHeader = Test-ZipMagicBytes -Path $Path
        
        if ($hasPKHeader -and $fileExtension -ne ".jar") {
            $result.IsRenamedJar = $true
            $result.IsDetected = $true
            $result.Confidence = "HIGH"
        }
        
        if (-not $hasPKHeader) {
            $result.Error = "File is not a JAR/ZIP file (missing PK header)"
            return $result
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $jar = [System.IO.Compression.ZipFile]::OpenRead($Path)
        
        $classFiles = $jar.Entries | Where-Object { $_.FullName -like "*.class" }
        $classCount = $classFiles.Count
        
        if ($classCount -gt 30) {
            $jar.Dispose()
            $result.Error = "Skipped: Too many classes ($classCount) - likely legitimate library"
            return $result
        }
        
        if ($classCount -eq 0) {
            $jar.Dispose()
            $result.Error = "No .class files found in JAR"
            return $result
        }
        
        $allBytes = @()
        
        foreach ($entry in $classFiles) {
            $stream = $entry.Open()
            $reader = New-Object System.IO.BinaryReader($stream)
            $bytes = $reader.ReadBytes([int]$entry.Length)
            $allBytes += $bytes
            $reader.Close()
            $stream.Close()
        }
        
        $jar.Dispose()
        
        foreach ($pattern in $script:BytePatterns) {
            $patternBytes = ConvertHex-ToBytes -hexString $pattern.Bytes
            
            if (Search-BytePattern -data $allBytes -pattern $patternBytes) {
                $result.BytePatternMatches += $pattern.Name
            }
        }
        
        foreach ($className in $script:ClassPatterns) {
            if (Search-ClassPattern -data $allBytes -className $className) {
                $result.ClassNameMatches += $className
            }
        }
        
        $result.SingleLetterClasses = Find-SingleLetterClasses -Path $Path
        
        $byteMatchCount = $result.BytePatternMatches.Count
        $classMatchCount = $result.ClassNameMatches.Count
        $singleLetterCount = $result.SingleLetterClasses.Count
        
        if ($byteMatchCount -ge 2) {
            $result.IsDetected = $true
            $result.Confidence = "HIGH"
        }
        elseif ($byteMatchCount -eq 1 -and ($classMatchCount -ge 5 -or $singleLetterCount -ge 5)) {
            $result.IsDetected = $true
            $result.Confidence = "MEDIUM"
        }
        elseif ($byteMatchCount -eq 1) {
            $result.IsDetected = $true
            $result.Confidence = "LOW"
        }
        elseif ($singleLetterCount -ge 8 -and $classMatchCount -ge 3) {
            $result.IsDetected = $true
            $result.Confidence = "MEDIUM"
        }
        elseif ($singleLetterCount -ge 5 -or $classMatchCount -ge 5) {
            $result.IsDetected = $true
            $result.Confidence = "LOW"
        }
        
        if ($result.IsRenamedJar -and $result.Confidence -eq "NONE") {
            $result.Confidence = "MEDIUM"
        }
        
    } catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Start-DoomsdayScan {
    param(
        [switch]$Debug,
        [switch]$Quiet
    )
    
    $Script:QuietMode = $Quiet
    $script:DebugMode = $Debug
    
    if (-not $Quiet) { Write-Banner }
    
    if (-not (Test-Administrator)) {
        if (-not $Quiet) {
            Write-Error "Administrator privileges required!"
            Write-Warning "Please launch CMD or PowerShell as admin!"
        }
        return
    }
    
    # Detect Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if (-not $Quiet) { Write-Info "Windows Version: $($osVersion.Major).$($osVersion.Minor) Build $($osVersion.Build)" }
    
    if ($osVersion.Major -eq 10) {
        if ($osVersion.Build -ge 22000) {
            if (-not $Quiet) { Write-Success "Detected: Windows 11" }
        } else {
            if (-not $Quiet) { Write-Success "Detected: Windows 10" }
        }
    }
    if (-not $Quiet) { Write-Host "" }
    
    if (-not $Quiet) { Write-Info "Extracting file indexes..." }
    
    $systemPath = "C:\Windows\" + "Pre" + "fetch"
    
    if (-not (Test-Path $systemPath)) {
        if (-not $Quiet) { Write-Error "Prefetch directory not found: $systemPath" }
        return
    }
    
    $javaFiles = Get-ChildItem -Path $systemPath -Filter "JAVA*.EXE-*.pf" -ErrorAction SilentlyContinue
    
    if ($javaFiles.Count -eq 0) {
        if (-not $Quiet) {
            Write-Warning "No JAVA prefetch files found in $systemPath"
            Write-Info "This could mean:"
            Write-System "- Java has never been run on this system"
            Write-System "- Prefetch files have been cleared"
            Write-System "- Prefetch is disabled"
        }
        return
    }
    
    if (-not $Quiet) { Write-Success "Found $($javaFiles.Count) JAVA prefetch file(s)" }
    
    $allJarPaths = @()
    $fileMetadata = @{}
    $processedFiles = 0
    $successfulParsing = 0
    
    foreach ($sysFile in $javaFiles) {
        $processedFiles++
        Write-ScanProgress -CurrentValue $processedFiles -TotalValue $javaFiles.Count
        
        if ($script:DebugMode) {
            if (-not $Quiet) {
                Write-Info "[DEBUG] ======================================"
            }
        }
        
        $indexes = Get-SystemIndexes -FilePath $sysFile.FullName
        
        if ($indexes.Count -eq 0) {
            if ($script:DebugMode) {
                if (-not $Quiet) { Write-Warning "  [DEBUG] No indexes extracted from $($sysFile.Name)" }
            }
            continue
        }
        
        $successfulParsing++
        
        if ($script:DebugMode) {
            if (-not $Quiet) { Write-Success "  [DEBUG] Successfully extracted $($indexes.Count) paths" }
        }
        
        $indexNum = 0
        foreach ($index in $indexes) {
            $indexNum++
            
            # Strip volume GUID if present, assume C: drive initially
            if ($index -match '\\VOLUME\{[^\}]+\}\\(.*)$') {
                $relativePath = $Matches[1]
                $assumedPath = "C:\$relativePath"
                $allJarPaths += $assumedPath
                
                if (-not $fileMetadata.ContainsKey($assumedPath)) {
                    $fileMetadata[$assumedPath] = @{
                        SourceFile = $sysFile.Name
                        IndexNumber = $indexNum
                        OriginalPath = $index
                    }
                }
            }
            else {
                # No volume GUID, use path as-is
                $allJarPaths += $index
                
                if (-not $fileMetadata.ContainsKey($index)) {
                    $fileMetadata[$index] = @{
                        SourceFile = $sysFile.Name
                        IndexNumber = $indexNum
                        OriginalPath = $index
                    }
                }
            }
        }
    }
    
    if (-not $Quiet) {
        Write-Host
        Write-Success "Prefetch files successfully parsed: $successfulParsing / $processedFiles"
        Write-Success "Total file paths extracted: $($allJarPaths.Count)"
    }
    
    if ($allJarPaths.Count -eq 0) {
        if (-not $Quiet) {
            Write-Warning "No file paths could be extracted from prefetch files"
            Write-Info "Possible issues:"
            Write-System "- Prefetch parsing failed (incompatible format)"
            Write-System "- No Java applications with file references"
            Write-Info "Try running with -Debug flag for more information:"
            Write-System ".\doomsday-scanner-usn.ps1 -Debug"
        }
        return
    }
    
    $uniquePaths = $allJarPaths | Select-Object -Unique
    if (-not $Quiet) { Write-Success "Unique files to scan: $($uniquePaths.Count)" }
    
    if (-not $Quiet) { Write-Info "Checking file existence across all drives..." }
    
    $existingPaths = @{}  # Store path -> actual location
    $trulyMissingPaths = @()
    $checkCount = 0
    $outsideRangeCount = 0
    $resolvedToDifferentDrive = 0
    
    # Get all available drives
    $allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | ForEach-Object { $_.Root.Substring(0, 1) }
    
    foreach ($path in $uniquePaths) {
        $checkCount++
        
        $foundPath = $null
        
        # First, check if file exists at the given path (usually C:)
        if (Test-Path $path -PathType Leaf) {
            $foundPath = $path
        }
        else {
            # File doesn't exist at assumed location
            # Try to find it on other drives
            if ($path -match '^[A-Z]:\\(.*)$') {
                $relativePath = $Matches[1]
                
                # Try each drive
                foreach ($drive in $allDrives) {
                    $testPath = "$drive`:\$relativePath"
                    
                    if (Test-Path $testPath -PathType Leaf) {
                        $foundPath = $testPath
                        $resolvedToDifferentDrive++
                        
                        if ($script:DebugMode) {
                            if (-not $Quiet) { Write-Info "  [DEBUG] Found on different drive: $testPath (assumed $path)" }
                        }
                        break
                    }
                }
            }
        }
        
        if ($foundPath) {
            # File exists somewhere
            $fileSize = (Get-Item $foundPath -ErrorAction SilentlyContinue).Length
            
            if ($fileSize -ge 200KB -and $fileSize -le 15MB) {
                $existingPaths[$path] = $foundPath
            } else {
                $outsideRangeCount++
                if ($script:DebugMode) {
                    $sizeMB = [math]::Round($fileSize / 1MB, 2)
                    if (-not $Quiet) { Write-System "  [DEBUG] Skipped (size: $sizeMB MB): $foundPath" }
                }
            }
        }
        else {
            # File doesn't exist on ANY drive - truly missing
            $trulyMissingPaths += $path
        }
    }
    
    $missingCount = $trulyMissingPaths.Count
    
    if (-not $Quiet) {
        Write-Info "Total paths checked: $checkCount"
        Write-Success "Files found and in size range (200KB-15MB): $($existingPaths.Count)"
        if ($resolvedToDifferentDrive -gt 0) {
            Write-Info "Files resolved to different drives: $resolvedToDifferentDrive"
        }
        Write-System "Files outside size range: $outsideRangeCount"
        Write-Warning "Files truly missing (not on any drive): $missingCount"
    }
    
    # Show truly missing files (filter out temp files, focus on JARs/EXEs)
    if ($missingCount -gt 0 -and -not $Quiet) {
        Write-Info "Truly missing files (deleted from all drives):"
        
        $displayedCount = 0
        foreach ($missingPath in $trulyMissingPaths) {
            # Skip temp files and Java cleanup
            # Only skip JNA####.DLL patterns, not ALL .DLLs
            if ($missingPath -match '\\TEMP\\|\\TMP\\|HSPERFDATA|\.TMP$|JNA\d+\.DLL') {
                continue
            }
            
            # Show JAR, EXE, and DLL files
            if ($missingPath -notmatch '\.(JAR|EXE|DLL)$') {
                continue
            }
            
            $displayedCount++
            Write-Warning "[DELETED] $missingPath"
            Write-Info "      Source: $($fileMetadata[$missingPath].SourceFile)"
        }
        
        if ($displayedCount -eq 0) {
            Write-Success "No suspicious deletions found (only temp files deleted)"
        }
    }
    
    if ($existingPaths.Count -eq 0) {
        if (-not $Quiet) {
            Write-Warning "No files exist to scan"
            Write-Info "All extracted paths point to files that either:"
            Write-System "- No longer exist (deleted)"
            Write-System "- Are outside the 200KB-15MB size range"
        }
        return
    }
    
    if (-not $Quiet) { Write-Info "Scanning files for Doomsday Client..." }
    
    $detections = @()
    $scanned = 0
    $skipped = 0
    
    foreach ($assumedPath in $existingPaths.Keys) {
        $actualPath = $existingPaths[$assumedPath]
        $scanned++
        
        $filename = [System.IO.Path]::GetFileName($actualPath)
        
        Write-ScanProgress -CurrentValue $scanned -TotalValue $existingPaths.Count
        
        try {
            $result = Test-DoomsdayClient -Path $actualPath
            
            if ($result.Error -and $result.Error -like "Skipped:*") {
                $skipped++
            }
            
            if ($result.IsDetected) {
                
                $detections += [PSCustomObject]@{
                    Path = $actualPath
                    SourceFile = $fileMetadata[$assumedPath].SourceFile
                    IndexNumber = $fileMetadata[$assumedPath].IndexNumber
                    Confidence = $result.Confidence
                    IsRenamedJar = $result.IsRenamedJar
                    BytePatterns = $result.BytePatternMatches.Count
                    ClassMatches = $result.ClassNameMatches.Count
                    SingleLetterClasses = $result.SingleLetterClasses.Count
                }
                
                if (-not $Quiet) {
                    Write-Error "[!] DETECTION: $actualPath"
                    Write-Info "    Confidence: $($result.Confidence)"
                    
                    if ($result.IsRenamedJar) {
                        Write-Error "    Renamed JAR detected!"
                    }
                    if ($result.BytePatternMatches.Count -gt 0) {
                        Write-Error "    Byte patterns: $($result.BytePatternMatches.Count)"
                    }
                }
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Error "Error scanning $filename : $_"
            }
        }
    }
    
    if (-not $Quiet) {
        Write-Host
        
        Write-Section -Title "PREFETCH SCAN COMPLETE"
        
        $summary = [
            ordered] @{
            'Total indexes extracted' = $allJarPaths.Count
            'Files in size range' = $uniquePaths.Count
            'Files exist' = $existingPaths.Count
            'Files scanned' = $scanned
            'Files skipped (>30 classes)' = $skipped
        }
        Write-Summary -SummaryData $summary
        
        if ($detections.Count -gt 0) {
            Write-Error "Doomsday Client detections: $($detections.Count)"
            
            $high = ($detections | Where-Object { $_.Confidence -eq "HIGH" }).Count
            $medium = ($detections | Where-Object { $_.Confidence -eq "MEDIUM" }).Count
            $low = ($detections | Where-Object { $_.Confidence -eq "LOW" }).Count
            
            if ($high -gt 0) { Write-Error "  HIGH: $high" }
            if ($medium -gt 0) { Write-Warning "  MEDIUM: $medium" }
            if ($low -gt 0) { Write-System "  LOW: $low" }
            
            Write-Error "DOOMSDAY CLIENT DETECTED ON THIS SYSTEM!"
            
            Write-Section -Title "PREFETCH DETECTION DETAILS"
            
            $results = @()
            foreach($detection in $detections){
                $results += [pscustomobject]@{
                    ID = $results.Count + 1
                    Path = $detection.Path
                    Source = $detection.SourceFile
                    Confidence = $detection.Confidence
                    Renamed = $detection.IsRenamedJar
                    BytePatterns = $detection.BytePatterns
                    ClassMatches = $detection.ClassMatches
                    SingleLetterClasses = $detection.SingleLetterClasses
                }
            }
            Write-Table -Data $results -Headers 'ID', 'Path', 'Source', 'Confidence', 'Renamed', 'BytePatterns', 'ClassMatches', 'SingleLetterClasses'

        } else {
            Write-Success "No Doomsday Client detected in prefetch analysis!"
        }
        
        if ($script:DebugMode) {
            Write-Info "[DEBUG MODE] Prefetch scan completed with debugging enabled"
        }
    }
    
    # Return the results for the consolidated report
    return @{
        Detections = $detections
        TotalIndexes = $allJarPaths.Count
        FilesInSizeRange = $uniquePaths.Count
        FilesExist = $existingPaths.Count
        FilesScanned = $scanned
        FilesSkipped = $skipped
    }
}

# Main execution entry point
function Main {
    while ($true) {
        $selection = Show-MainMenu
        switch ($selection) {
            '1' { 
                $mainReport = Start-ProfessionalScan @args
                $prefetchResults = Start-DoomsdayScan -Quiet:$true
                
                Write-Section -Title "CONSOLIDATED SCAN RESULTS"
                
                Write-Info "MAIN ADVANCED ANALYSIS RESULTS:"
                if ($mainReport.DetailedDetections.Count -gt 0) {
                    Write-Error "Detections found: $($mainReport.DetailedDetections.Count)"
                    $results = @()
                    foreach($detection in $mainReport.DetailedDetections){
                        $results += [pscustomobject]@{
                            ID = $results.Count + 1
                            File = $detection.FilePath
                            Confidence = $detection.Confidence
                            Score = $detection.ThreatScore
                        }
                    }
                    Write-Table -Data $results -Headers 'ID', 'File', 'Confidence', 'Score'
                } else {
                    Write-Success "No threats detected by main analysis"
                }
                
                Write-Info "PREFETCH ANALYSIS RESULTS (2nd.ps1):"
                if ($prefetchResults -and $prefetchResults.Detections.Count -gt 0) {
                    Write-Error "Detections found: $($prefetchResults.Detections.Count)"
                    $results = @()
                    foreach($detection in $prefetchResults.Detections){
                        $results += [pscustomobject]@{
                            ID = $results.Count + 1
                            Path = $detection.Path
                            Source = $detection.SourceFile
                            Confidence = $detection.Confidence
                        }
                    }
                    Write-Table -Data $results -Headers 'ID', 'Path', 'Source', 'Confidence'
                } else {
                    Write-Success "No threats detected by prefetch analysis"
                }
                
                Write-Section -Title "SCANNING COMPLETE"
            }
            '2' { Write-Warning "Not implemented yet." }
            '3' { Write-Warning "Not implemented yet." }
            '4' { Write-Success "Exiting scanner. Goodbye!"; break }
            default {
                Write-Error "Invalid selection. Please try again."
                Start-Sleep -Seconds 2
            }
        }
        if ($selection -in '1', '2', '3') {
            Read-Host "Press Enter to return to the main menu..."
        }
    }
}

Main
