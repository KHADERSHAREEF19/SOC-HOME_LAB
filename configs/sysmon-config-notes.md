# Sysmon & Windows Audit Policy Notes

**Target host:** Windows Server 2022 Domain Controller (`192.168.1.11`)
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

> **Splunk note:** the Universal Forwarder must collect this channel with
> `renderXml = true` (already set in [`inputs.conf`](inputs.conf)), which is what makes
> fields like `Image`, `CommandLine`, `ParentCommandLine` and `TargetFilename`
> searchable in SPL.

## Why Sysmon?

Windows Security logs tell us *who authenticated, who queried AD, and what policy changed*.
Sysmon tells us *what actually executed on the box* — process trees, file writes,
registry changes. Together they form the telemetry a modern SOC relies on, and both
ship through the same forwarder pipeline into `index=main`.

## Key Sysmon Event IDs used in this lab

| EID | Event | Used by | ATT&CK relevance |
|-----|-------|---------|------------------|
| 1 | Process creation | SIM-03, SIM-05 | T1059.001 |
| 3 | Network connection | SIM-03/06 pivots (delivery channel) | T1105, T1071 |
| 11 | File created | SIM-06 | T1204.002 |
| 12 / 13 | Registry object/value set | Stretch goals (autoruns) | T1547.001 |
| 22 | DNS query | C2 lookups (stretch goal) | T1071.004 |

## Windows Security Event IDs (the AD/DC layer)

| EID | Event | Used by | Detection SPL |
|-----|-------|---------|---------------|
| 4624 | Successful logon | SIM-02 | [`02-brute-force.spl`](../queries/02-brute-force.spl) |
| 4625 | Failed logon | SIM-02 | [`02-brute-force.spl`](../queries/02-brute-force.spl) |
| 4661 / 4662 | AD object access / handle request | SIM-01 | [`01-ad-enumeration.spl`](../queries/01-ad-enumeration.spl) |
| 4720 | User account created | SIM-04 | [`04-account-persistence.spl`](../queries/04-account-persistence.spl) |
| 4728 | Member added to global group (Domain Admins) | SIM-04 | [`04-account-persistence.spl`](../queries/04-account-persistence.spl) |
| 4732 | Member added to local group (Administrators) | SIM-04 | [`04-account-persistence.spl`](../queries/04-account-persistence.spl) |
| 1102 | Audit log cleared | SIM-05 | [`05-log-wipe.spl`](../queries/05-log-wipe.spl) |
| 7036 (System) | Service state change (forwarder stopped) | SIM-05 | pivot in the runbook |

## Audit policy used (Domain Controller baseline)

Without these, the DC generates the *events* but doesn't write them — audit policy is
the prerequisite for every detection in this repo. Enable via GPO (Default Domain
Controller Policy) or `auditpol`:

```powershell
# Credential / logon telemetry (SIM-02)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# AD object access (SIM-01 — 4661/4662)
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Audit-log-wipe detection (SIM-05 — 1102 is always logged when the log is cleared,
# but Policy Change auditing documents the surrounding actions)
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

# Process creation + command line (enriches triage)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

> For 4662 to be truly useful you also enable **object-level SACL auditing** on key AD
> objects (e.g. the Domain object → Properties → Security → Advanced → Auditing →
> "Everyone: List contents"). In the lab, enabling it on the domain root is enough to see
> enumeration bursts — exactly the setup an enterprise AD security baseline requires,
> and a strong interview talking point.
