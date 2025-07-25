<#
.SYNOPSIS
    Detects unquoted service paths, evaluates writability, privilege level, and flags high-risk services.

.DESCRIPTION
    Scans for unquoted paths in services. Checks if the directory is writable (only if non-admin) and if the service runs under a privileged account.
    Adds a "HighRisk" column to flag exploitable combinations.

.OUTPUT
    CSV saved to Desktop with complete analysis.

.AUTHOR
    Port Zero Cyber Solutions
#>

function Test-PathWritableAsUser {
    param ([string]$Path)
    try {
        $temp = [System.IO.Path]::Combine($Path, [System.IO.Path]::GetRandomFileName())
        $file = New-Item -Path $temp -ItemType File -Force -ErrorAction Stop
        Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Is-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Is-PrivilegedAccount {
    param ([string]$account)
    return ($account -match "LocalSystem|NetworkService|LocalService")
}

# Setup
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$outputPath = "$env:USERPROFILE\OneDrive\Desktop\UnquotedServicePaths_HighRisk_$timestamp.csv"
$isAdmin = Is-Admin
Write-Host "`n[+] Running as Administrator: $isAdmin" -ForegroundColor Yellow
Write-Host "[+] Scanning for unquoted service paths with risk triage...`n" -ForegroundColor Cyan

$results = @()
$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -ne $null }

foreach ($service in $services) {
    $rawPath = $service.PathName.Trim()
    if ([string]::IsNullOrWhiteSpace($rawPath) -or $rawPath.StartsWith('"')) {
        continue
    }

    if ($rawPath -match '\s') {
        $exePath = $rawPath.Split(" ")[0]
        $folderPath = Split-Path $exePath -Parent
        $account = $service.StartName
        $writable = $false
        $highRisk = $false

        if (-not $isAdmin -and (Test-Path $folderPath)) {
            $writable = Test-PathWritableAsUser -Path $folderPath
        }

        if ($writable -and (Is-PrivilegedAccount -account $account)) {
            $highRisk = $true
        }

        Write-Host "[!] Found: $($service.Name) | Account: $account | Writable: $writable | HighRisk: $highRisk" -ForegroundColor Yellow

        $results += [PSCustomObject]@{
            ServiceName     = $service.Name
            DisplayName     = $service.DisplayName
            StartMode       = $service.StartMode
            StartAccount    = $account
            ImagePath       = $rawPath
            DirectoryPath   = $folderPath
            WritableByUser  = $writable
            HighRisk        = $highRisk
        }
    }
}

# Export
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Report with HighRisk column saved to: $outputPath" -ForegroundColor Green
} else {
    Write-Host "`n[+] No unquoted service paths detected." -ForegroundColor Green
}
