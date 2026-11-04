# Windows Server 2025 STIG remediation

**Eleven security settings on a Windows Server 2025 host, fixed and proven: each one failed the official US government
checklist on the baseline audit, and passed on the rescan.**

The checklist is the DISA STIG for Windows Server 2025, the security standard the US Department of Defense requires
on its servers. Each setting was fixed with a PowerShell script and confirmed by a Tenable scan that logs in to the
server and checks it against the checklist.

- **Checklist:** DISA Microsoft Windows Server 2025 STIG V1R3, run as a Tenable Vulnerability Management compliance scan.
- **Target:** `mjaylabs-stig01`, a Windows Server 2025 virtual machine in Microsoft Azure, part of the MjayLabs
  vulnerability management lab.
- **Before:** 267 checks: 103 failed, 4 errors or warnings, 160 passed (3 Nov 2026, 19:10 UTC).
- **After:** [XX] failed, [X] errors or warnings, [XXX] passed. All eleven targeted settings pass.

## The eleven settings

<img src="images/MjayLabs_STIG_Remediation_Targets.png" width="100%" alt="Eleven DISA STIG findings on mjaylabs-stig01 selected for remediation. 267 checks audited, 103 failed, 11 selected, fixed in two PowerShell waves. All are CAT II. Wave 1: NTLM client session security, PowerShell script block logging, audit registry failures, audit registry successes. Wave 2: NTLM server session security, force audit subcategory settings, block NTLM null session fallback, PowerShell transcription, command line in process events, security event log size, print drivers over HTTP.">

<details><summary>The eleven as a table, with checklist IDs and scripts</summary>

| STIG ID | Vuln-ID | Finding | Before | After | Script |
|---|---|---|---|---|---|
| WN25-SO-000330 | V-278227 | NTLM SSP clients require NTLMv2 session security and 128-bit encryption | Failed | Passed | [Wave 1](scripts/Remediate-STIG-Wave1.ps1) |
| WN25-CC-000460 | V-278124 | PowerShell script block logging enabled | Failed | Passed | [Wave 1](scripts/Remediate-STIG-Wave1.ps1) |
| WN25-AU-000585 | V-279920 | Audit Object Access - Registry (Failure) | Failed | Passed | [Wave 1](scripts/Remediate-STIG-Wave1.ps1) |
| WN25-AU-000586 | V-279921 | Audit Object Access - Registry (Success) | Failed | Passed | [Wave 1](scripts/Remediate-STIG-Wave1.ps1) |
| WN25-SO-000340 | V-278228 | NTLM SSP servers require NTLMv2 session security and 128-bit encryption | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |
| WN25-SO-000050 | V-278199 | Audit subcategory settings override category settings | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |
| WN25-SO-000270 | V-278221 | NTLM prevented from falling back to a null session | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |
| WN25-CC-000530 | V-278131 | PowerShell transcription enabled | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |
| WN25-CC-000090 | V-278088 | Command line data included in process creation events | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |
| WN25-CC-000280 | V-278106 | Security event log size (196608 KB) | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |
| WN25-CC-000150 | V-278093 | Downloading print driver packages over HTTP turned off | Failed | Passed | [Wave 2](scripts/Remediate-STIG-Wave2.ps1) |

</details>

## Method

1. Run the DISA Windows Server 2025 STIG audit as a credentialed Tenable scan and record every failed check.
2. Choose findings that are CAT II (medium severity), can be fixed with a scripted, reversible change, and won't cut
   off RDP access or the scan account.
3. Group them into two PowerShell waves. Each script saves the current value to `C:\Rollback\` before changing it,
   then prints the new value back as evidence.
4. Run each script as Administrator on the VM and reboot.
5. Rescan with the same scan and confirm each finding moved from Failed to Passed under **Findings > Host Audits**
   (Tenable plugin 21156, Windows Compliance Checks).

## What was left out, and why

- **Account lockout (WN25-AC-000010 to -000030):** a three-attempt lockout could lock out the Tenable scan account and
  break every later scan.
- **CAT I findings such as AutoRun and AlwaysInstallElevated:** outside the intermediate scope of this round.
- **TPM and Secure Boot (WN25-00-000090, -000470):** these depend on the Azure VM's security type, not on a script.

## Lessons learned

- **A setting can look hardened and still fail.** `NtlmMinClientSec` was already `536870912` (128-bit encryption
  only). The STIG requires `537395200` (`0x20080000`), which adds NTLMv2 session security. Bitmask values have to be
  read, not just checked for being set.
- **One change can close two findings.** Enabling Registry auditing for both Success and Failure closed
  WN25-AU-000585 and -000586. The NTLM client and server settings take the same value, so they were fixed as a pair.
- **Audit settings depend on each other.** Registry auditing and process-creation command lines only produce reliable
  evidence when advanced audit subcategories override legacy category settings (WN25-SO-000050), so that was fixed in
  the same project.
- **Logging is the evidence trail.** Script block logging (event 4104), transcription, and command lines in process
  creation events (event 4688) record exactly the evidence a threat hunt or incident response depends on.
- **CIS and STIG are different checklists.** An earlier audit in this lab used the CIS Windows Server 2025 Benchmark.
  The two overlap heavily but use different IDs and severities, so results have to be reported against the checklist
  that was actually run.

## Using the scripts

Each wave script is standalone. Run it in an elevated PowerShell on the target, reboot, then rescan. Prior values are
saved to `C:\Rollback\` and rollback commands are in each script's footer. The scripts only set the values their STIGs
check; review them before running anywhere that is not a lab.

---

[Your Name] · [github.com/your-username](https://github.com/your-username) · [linkedin.com/in/your-profile](https://linkedin.com/in/your-profile)
