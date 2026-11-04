<#
.SYNOPSIS
    WN25-SO-000340 - NTLM SSP servers must require NTLMv2 session security and 128-bit encryption

.DESCRIPTION
    Blocks weak inbound NTLM sessions. Same 0x20080000 bitmask as the client-side setting (WN25-SO-000330).

.NOTES
    Benchmark : DISA Microsoft Windows Server 2025 STIG V1R3
    Vuln-ID   : V-278228
    Severity  : CAT II
    Target    : mjaylabs-stig01 (Windows Server 2025, Azure lab)
    Verify    : Rescan, then Tenable > Findings > Host Audits, plugin 21156,
                search "WN25-SO-000340". Expected result: Passed.
    Run as    : Administrator. Lab use only; review before running elsewhere.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$StigId   = 'WN25-SO-000340'
$Rollback = 'C:\Rollback'
New-Item -ItemType Directory -Path $Rollback -Force | Out-Null
$Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$Name  = 'NtlmMinServerSec'
$Value = 537395200   # 537395200 (0x20080000)

# Save the current value for rollback
$Before = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
if ($null -eq $Before) { $Before = 'NOT SET' }
"$StigId | $Path | $Name | before=$Before" | Out-File "$Rollback\$StigId.txt" -Encoding utf8

# Apply the STIG setting
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null

# Print the value back as evidence
$After = (Get-ItemProperty -Path $Path -Name $Name).$Name
Write-Host "$StigId : $Name changed from $Before to $After"
if ($After -eq $Value) {
    Write-Host "[PASS] $StigId remediated. Rescan to confirm." -ForegroundColor Green
} else {
    Write-Host "[FAIL] $StigId value did not apply." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# Rollback (run manually only if needed):
#   Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Value 536870912
# -----------------------------------------------------------------------------
