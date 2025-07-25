<#
.SYNOPSIS
    Automatically corrects unquoted service paths to prevent privilege escalation.

.DESCRIPTION
    Detects unquoted service paths with spaces and updates them using sc.exe to enclose the path in quotes.
    Logs all actions and results to a timestamped log file.

.NOTES
    Must be run as Administrator.
    Author: Port Zero Cyber Solutions
#>

# Generate log path
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$logPath = "$env:USERPROFILE\OneDrive\Desktop\UnquotedPathFixLog_$timestamp.txt"
Add-Content -Path $logPath -Value "Remediation Log - $timestamp`n"

# Get all services
$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -ne $null }

foreach ($service in $services) {
    $path = $service.PathName.Trim()

    if ([string]::IsNullOrWhiteSpace($path) -or $path.StartsWith('"')) {
        continue
    }

    # Check for space in path and not already quoted
    if ($path -match '\s') {
        # Extract exe path only (remove args)
        $exe = $path.Split(" ")[0]
        $args = $path.Substring($exe.Length).Trim()

        # Construct quoted path
        $quotedPath = "`"$exe`""
        if ($args) {
            $quotedPath += " $args"
        }

        try {
            # Run sc config to fix it
            $cmd = "sc.exe config `"$($service.Name)`" binPath= `"$quotedPath`""
            Invoke-Expression $cmd

            $log = "[FIXED] $($service.Name) → $quotedPath"
            Write-Host $log -ForegroundColor Green
            Add-Content -Path $logPath -Value $log
        }
        catch {
            $log = "[FAILED] $($service.Name) → $_"
            Write-Host $log -ForegroundColor Red
            Add-Content -Path $logPath -Value $log
        }
    }
}

Write-Host "`n[+] Quoting complete. Log saved to: $logPath" -ForegroundColor Cyan
