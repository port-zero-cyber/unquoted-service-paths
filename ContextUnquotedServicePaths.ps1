<#
.SYNOPSIS
    Detects unquoted service paths and adds service account context for risk assessment.

.DESCRIPTION
    Finds unquoted executable paths in Windows services and checks if any part is exploitable due to user-write permissions. 
    It also includes the account the service runs under (e.g., LocalSystem) for prioritization.

.OUTPUT
    A detailed CSV report saved to the Desktop.

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

# Output path
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$outputPath = "$env:USERPROFILE\OneDrive\Desktop\UnquotedServicePaths_Context_$timestamp.csv"

$isAdmin = Is-Admin
Write-Host "`n[+] Running as Administrator: $isAdmin" -ForegroundColor Yellow
Write-Host "[+] Scanning for unquoted service paths with context...`n" -ForegroundColor Cyan

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
        $writable = $false

        if (-not $isAdmin -and (Test-Path $folderPath)) {
            $writable = Test-PathWritableAsUser -Path $folderPath
        }

        $account = $service.StartName

        Write-Host "[!] Unquoted Path Found: $($service.Name) | Account: $account" -ForegroundColor Yellow

        $results += [PSCustomObject]@{
            ServiceName     = $service.Name
            DisplayName     = $service.DisplayName
            StartMode       = $service.StartMode
            StartAccount    = $account
            ImagePath       = $rawPath
            DirectoryPath   = $folderPath
            WritableByUser  = $writable
        }
    }
}

# Export to CSV
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Detailed report saved to: $outputPath" -ForegroundColor Green
} else {
    Write-Host "`n[+] No unquoted service paths detected." -ForegroundColor Green
}
