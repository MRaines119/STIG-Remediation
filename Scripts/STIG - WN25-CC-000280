<#
.SYNOPSIS
    WN25-CC-000280 - Windows Server 2025 Security event log size must hold at least one
    week of audit records

.DESCRIPTION
    Sets the Security log maximum size by policy. The STIG's 196608 KB is only an
    example ("the value must equal at least one week's worth of records"), and the
    Tenable audit can require a larger value. Version 1 of this script set 196608,
    which the audit failed.

.PARAMETER MaxSizeKB
    Maximum Security log size in KB. Set it to the "Policy Value" shown for this check
    in Tenable (Findings > Host Audits > WN25-CC-000280). Default: 196608.
    Example: .\10-WN25-CC-000280.ps1 -MaxSizeKB 5120000

.NOTES
    Benchmark : DISA Microsoft Windows Server 2025 STIG V1R3
    Vuln-ID   : V-278106
    Severity  : CAT II
    Target    : mjaylabs-stig01 (Windows Server 2025, Azure lab)
    Verify    : Rescan, then Tenable > Findings > Host Audits, plugin 21156,
                search "WN25-CC-000280". Expected result: Passed.
    Run as    : Administrator. Lab use only; review before running elsewhere.
#>
#Requires -RunAsAdministrator
param([int]$MaxSizeKB = 196608)
$ErrorActionPreference = 'Stop'
$StigId   = 'WN25-CC-000280'
$Rollback = 'C:\Rollback'
New-Item -ItemType Directory -Path $Rollback -Force | Out-Null
$Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$Name = 'MaxSize'

# Save the current value for rollback
$Before = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
if ($null -eq $Before) { $Before = 'NOT SET' }
"$StigId | $Path | $Name | before=$Before" | Out-File "$Rollback\$StigId.txt" -Encoding utf8

# Apply the STIG setting (policy key) and resize the live log to match
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
New-ItemProperty -Path $Path -Name $Name -Value $MaxSizeKB -PropertyType DWord -Force | Out-Null
wevtutil sl Security /ms:$([int64]$MaxSizeKB * 1024)

# Print the value back as evidence
$After = (Get-ItemProperty -Path $Path -Name $Name).$Name
Write-Host "$StigId : $Name changed from $Before to $After KB"
if ($After -ge $MaxSizeKB) {
    Write-Host "[PASS] $StigId remediated. Rescan to confirm." -ForegroundColor Green
} else {
    Write-Host "[FAIL] $StigId value did not apply." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# Rollback (run manually only if needed):
#   Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize'
# -----------------------------------------------------------------------------
