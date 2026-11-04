<#
.SYNOPSIS
    WN25-CC-000530 - Windows Server 2025 must have PowerShell Transcription enabled

.DESCRIPTION
    Turns on PowerShell Transcription AND sets a transcript output directory, as the
    STIG's fix text requires ("Specify the Transcript output directory to point to a
    Central Log Server or another secure location to prevent user access").
    Version 1 of this script set only EnableTranscripting, which the Tenable audit failed.

.PARAMETER OutputDirectory
    Where transcripts are written. Default: C:\PSTranscripts (locked to SYSTEM and
    Administrators). In production, point this at a central log share instead.

.NOTES
    Benchmark : DISA Microsoft Windows Server 2025 STIG V1R3
    Vuln-ID   : V-278131
    Severity  : CAT II
    Target    : mjaylabs-stig01 (Windows Server 2025, Azure lab)
    Verify    : Rescan, then Tenable > Findings > Host Audits, plugin 21156,
                search "WN25-CC-000530". Expected result: Passed.
    Run as    : Administrator. Lab use only; review before running elsewhere.
#>
#Requires -RunAsAdministrator
param([string]$OutputDirectory = 'C:\PSTranscripts')
$ErrorActionPreference = 'Stop'
$StigId   = 'WN25-CC-000530'
$Rollback = 'C:\Rollback'
New-Item -ItemType Directory -Path $Rollback -Force | Out-Null
$Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'

# Save the current values for rollback
$Current = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
"$StigId | $Path | EnableTranscripting=$($Current.EnableTranscripting) | OutputDirectory=$($Current.OutputDirectory)" |
    Out-File "$Rollback\$StigId.txt" -Encoding utf8

# Create the transcript folder and restrict it to SYSTEM and Administrators
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
icacls $OutputDirectory /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

# Apply the STIG setting
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
New-ItemProperty -Path $Path -Name 'EnableTranscripting'     -Value 1 -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $Path -Name 'EnableInvocationHeader'  -Value 1 -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $Path -Name 'OutputDirectory' -Value $OutputDirectory -PropertyType String -Force | Out-Null

# Print the values back as evidence
$After = Get-ItemProperty -Path $Path
Write-Host "$StigId : EnableTranscripting=$($After.EnableTranscripting) OutputDirectory=$($After.OutputDirectory)"
if ($After.EnableTranscripting -eq 1 -and $After.OutputDirectory) {
    Write-Host "[PASS] $StigId remediated. Rescan to confirm." -ForegroundColor Green
} else {
    Write-Host "[FAIL] $StigId values did not apply." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# Rollback (run manually only if needed):
#   Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Recurse
# -----------------------------------------------------------------------------
