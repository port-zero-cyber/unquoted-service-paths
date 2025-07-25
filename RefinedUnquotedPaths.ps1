<#
.SYNOPSIS
    Detects unquoted service paths exploitable by non-admin users.

.DESCRIPTION
    Identifies services with unquoted executable paths that contain spaces. 
    Checks write access only if the current user is NOT an administrator to avoid false positives.

.OUTPUT
    CSV report saved to the Desktop with accurate writable path assessment.

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
$outputPath = "$env:USERPROFILE\OneDrive\Desktop\UnquotedServicePaths_Refined_$timestamp.csv"

$isAdmin = Is-Admin
Write-Host "`n[+] Running as Administrator: $isAdmin" -ForegroundColor Yellow
Write-Host "[+] Scanning for unquoted service paths...`n" -ForegroundColor Cyan

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

        # Only check for writability if NOT admin
        if (-not $isAdmin -and (Test-Path $folderPath)) {
            $writable = Test-PathWritableAsUser -Path $folderPath
        }

        Write-Host "[!] Unquoted Path Found: $($service.Name)" -ForegroundColor Yellow

        $results += [PSCustomObject]@{
            ServiceName    = $service.Name
            DisplayName    = $service.DisplayName
            StartMode      = $service.StartMode
            ImagePath      = $rawPath
            DirectoryPath  = $folderPath
            WritableByUser = $writable
        }
    }
}

# Export to CSV
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Report saved to: $outputPath" -ForegroundColor Green
} else {
    Write-Host "`n[+] No unquoted service paths detected." -ForegroundColor Green
}
