<#
.SYNOPSIS
    Detects unquoted service paths and checks for writable directories. Exports to CSV.

.DESCRIPTION
    Finds unquoted Windows service paths with spaces, and verifies if any part of the path is writable by the current user (potential privilege escalation vector).

.OUTPUT
    CSV report saved to Desktop.

.AUTHOR
    Port Zero Cyber Solutions
#>

function Test-PathWritable {
    param (
        [string]$Path
    )
    try {
        $temp = [System.IO.Path]::Combine($Path, [System.IO.Path]::GetRandomFileName())
        $null = New-Item -Path $temp -ItemType File -Force -ErrorAction Stop
        Remove-Item -Path $temp -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

Write-Host "`n[+] Scanning for unquoted service paths with writable directory checks..." -ForegroundColor Cyan

$results = @()

$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -ne $null }

foreach ($service in $services) {
    $rawPath = $service.PathName.Trim()

    if ([string]::IsNullOrWhiteSpace($rawPath) -or $rawPath.StartsWith('"')) {
        continue
    }

    if ($rawPath -match '\s') {
        # Extract just the executable path (remove parameters)
        $exePath = $rawPath.Split(" ")[0]

        # Get folder part
        $directory = Split-Path $exePath -Parent

        # Test write access
        $isWritable = if (Test-Path $directory) { Test-PathWritable -Path $directory } else { $false }

        Write-Host "`n[!] Unquoted Path Detected" -ForegroundColor Yellow
        Write-Host "    Service Name : $($service.Name)"
        Write-Host "    Image Path   : $rawPath"
        Write-Host "    Writable Dir : $isWritable"

        $results += [PSCustomObject]@{
            ServiceName     = $service.Name
            DisplayName     = $service.DisplayName
            StartMode       = $service.StartMode
            ImagePath       = $rawPath
            DirectoryPath   = $directory
            WritableByUser  = $isWritable
        }
    }
}

# Export results to CSV
if ($results.Count -gt 0) {
    $csvPath = "$env:USERPROFILE\OneDrive\Desktop\UnquotedServicePaths_Report.csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Report saved to: $csvPath" -ForegroundColor Green
} else {
    Write-Host "`n[+] No unquoted service paths found." -ForegroundColor Green
}
