# unquoted-service-paths
This is a repository of powershell scripts that assist organizations in finding, flagging, and remediating unquoted service paths within their environment. The scripts can be used to identify if standard users have high-risk writable permissions in system or administrative only service paths. 

### **Ensure open the file and change the output save location i.e., '$outputPath = "$env:USERPROFILE\DesiredLocation\"**

# Windows Unquoted Service Path Detection & Remediation Toolkit

A collection of PowerShell scripts designed to help cybersecurity professionals and IT administrators detect, triage, and remediate unquoted service path vulnerabilities on Windows systems, a common privilege escalation vector.

---

## Why This Matters

Unquoted service paths with spaces in them can be exploited by attackers to escalate privileges if any portion of the path is user-writable. This toolkit provides:

- Automated detection
- Context-aware triage
- Writable directory checks
- Safe remediation
- CSV reporting for audit or compliance

---

## Script Descriptions

### `FindUnquotedPaths.ps1`
> **Basic detection script**  
Scans for Windows services with unquoted executable paths that contain spaces. Flags potential misconfigurations.

- Detects services with unquoted paths
- No writability check
- No remediation

---

### `RefinedUnquotedPaths.ps1`
> **Improved scanner with smart writable path check**  
Adds a user-context-aware check to identify whether the service executable directory is writable **only if run as a non-admin**, avoiding false positives.

- Detects unquoted paths
- Verifies writable folder access (non-admin)
- CSV export for reporting

---

### `HighRiskFlagUnquotedServicePaths.ps1`
> **Full triage scanner with risk flag**  
Includes service account context (`LocalSystem`, `NetworkService`, etc.) and flags **high-risk combinations** of writable directories and privileged accounts.

- Everything from refined scanner
- Adds `StartAccount` and `HighRisk` columns
- Helps prioritize remediation

---

### `FixUnquotedPaths.ps1`
> **Automated remediation**  
Safely quotes all detected unquoted paths using `sc config`. Logs changes to a timestamped file on your Desktop.

- Auto-quotes paths with spaces
- Uses `sc.exe` for compatibility
- Generates a log file of fixes

---

## Output

Each scanner script exports a `.csv` file to the user’s Desktop (or other location as needed), including details like:

- Service name and display name
- Executable path
- Service account
- Directory write access
- High risk indicator (if applicable)

---

## Usage Instructions

1. Open **PowerShell as Administrator**
2. Run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\UnquotedServicePaths.ps1 (or similar .ps1 file)
