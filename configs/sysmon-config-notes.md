# Sysmon Deployment Notes

**Target host:** Windows 11 Enterprise (`192.168.1.11`)
**Config:** [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (industry-standard baseline)
**Install:**

```powershell
# Run as Administrator, from the folder containing both files
.\Sysmon64.exe -i sysmonconfig-export.xml
# Verify service state
Get-Service Sysmon64
```

**Update the config later (no reinstall):**

```powershell
.\Sysmon64.exe -c sysmonconfig-export.xml
```

## Why Sysmon?

Windows Security logs tell us *who authenticated and what policy changed*.
Sysmon tells us *what actually executed on the box* — process trees, network
connections, file writes, registry changes. Together they form the telemetry a
modern SOC (and any EDR) relies on.

## Key Sysmon Event IDs used in this lab

| EID | Event | Used by | ATT&CK relevance |
|-----|-------|---------|------------------|
| 1 | Process creation | SIM-03, SIM-04, SIM-05, SIM-01 | T1059, T1053, T1082 |
| 3 | Network connection | SIM-01 (optional visibility) | T1046, T1071 |
| 11 | File created | SIM-06 | T1204, T1105 |
| 12 / 13 | Registry object/value set | SIM-04 | T1547.001 |
| 22 | DNS query | C2 lookups (stretch goal) | T1071.004 |

## Companion Windows Security Event IDs

| EID | Event | Used by |
|-----|-------|---------|
| 4624 | Successful logon | SIM-02 |
| 4625 | Failed logon | SIM-02 |
| 4688 | Process creation (if audit policy enabled) | Cross-check with Sysmon 1 |
| 4698 | Scheduled task created | SIM-04 |
| 4720 | User account created | Stretch goal |
| 1102 | Audit log cleared | SIM-05 |

## Audit policy used (baseline)

```powershell
# Ensure process creation + command line auditing (feeds 4688 and enriches triage)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
# Include command line in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

> These settings mirror what a production workstation baseline (and CIS benchmarks) require —
> calling that out in interviews shows you understand telemetry as a prerequisite for detection.
