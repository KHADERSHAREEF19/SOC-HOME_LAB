# SIM-04 — Persistence: Account Creation & Group Elevation

| | |
|---|---|
| **ID** | SIM-04 |
| **ATT&CK** | T1136.001 Create Account: Domain Account · T1098 Account Manipulation · T1078 Valid Accounts |
| **Tactic** | Persistence |
| **Attacker** | Simulated foothold on the DC `192.168.1.11` (compromise of an admin-level session) |
| **Target** | Windows Server 2022 DC `192.168.1.11` (Active Directory) |
| **Detection** | Saved search **"Persistence - Account Creation and Group Elevation"** → [`queries/04-account-persistence.spl`](../queries/04-account-persistence.spl) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Install the **persistence mechanism attackers actually use on domain estates**: a rogue
account that survives password resets of the originally compromised credentials, plus
privilege elevation by adding it to admin groups. Detect all of it from the security events
that only a **Domain Controller** produces: 4720 (account created), 4732/4728 (added to
local/global admin groups).

## Scope & Safety

- Disposable lab accounts only (`svc_backdoor`) — deleted in the cleanup phase.
- All commands run on the lab DC; nothing touches any other system.

## Prerequisites

- [ ] Attacker session on the DC with local/domain admin rights (simulated compromise)
- [ ] Splunk receiving `WinEventLog:Security` (4720/4728/4732 audit categories enabled —
      see [`../configs/sysmon-config-notes.md`](../configs/sysmon-config-notes.md))
- [ ] Saved search deployed in [`../configs/savedsearches.conf`](../configs/savedsearches.conf)

---

## 1. Attack Execution

Run from an elevated command prompt on the DC (or over WinRM from Kali):

```cmd
:: Phase A — create the backdoor account (EventCode 4720)
net user svc_backdoor P@ssw0rd123 /add /domain

:: Phase B — elevate it (EventCode 4732: added to local Administrators)
net localgroup administrators svc_backdoor /add

:: Phase C — elevate into a domain privileged group (EventCode 4728)
net group "Domain Admins" svc_backdoor /add /domain

:: Verify — the attacker now has durable privileged access
net user svc_backdoor /domain
net group "Domain Admins" /domain
```

📸 Screenshot: `screenshots/08a_account_commands.png` — the `net user` / `net group`
commands and confirmations.

> **Why this beats "installing malware" as a persistence demo:** in real incident response,
  rogue accounts are one of the most common findings — and 4720/4728 alerts are the
  bread-and-butter of AD monitoring. Interviewers recognize this immediately.

## 2. Expected Telemetry

| Action | Source | EventCode | Fields in Splunk |
|--------|--------|-----------|------------------|
| Account created | `WinEventLog:Security` | **4720** | `TargetUserName=svc_backdoor`, `SubjectUserName` |
| Added to local Administrators | `WinEventLog:Security` | **4732** | `MemberName=svc_backdoor` |
| Added to Domain Admins | `WinEventLog:Security` | **4728** | `MemberName`, `SubjectUserName` |
| Detection | Saved search **Persistence - Account Creation and Group Elevation** | — | `Action` column: "User Account Created" / "Added to Local Admin Group" / "Added to Global Admin Group" |

📸 Screenshots:
- `screenshots/08b_event_4720_4728.png` — raw Security events in Splunk (event XML view)
- `screenshots/08_splunk_alert_account.png` — saved search results with the `Action` column

## 3. Detection (SPL)

Run in Splunk Web (raw file: [`04-account-persistence.spl`](../queries/04-account-persistence.spl)):

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732 OR EventCode=4728)
| eval Action=case(EventCode==4720, "User Account Created", EventCode==4732, "Added to Local Admin Group", EventCode==4728, "Added to Global Admin Group")
| table _time, Action, TargetUserName, MemberName, SubjectUserName
```

Note the `case()` mapping: raw EventCodes become **human-readable action labels** —
exactly the kind of analyst-friendly enrichment SOC teams expect in saved searches.

## 4. Triage Walkthrough

1. Open the results → build the story: who created what, and who elevated it?
   (`SubjectUserName` = the compromised admin; `TargetUserName`/`MemberName` = the backdoor.)
2. Legitimacy check: was this change part of a documented IT change/ticket? No → hostile.
3. Scope: how many accounts were created in the window? (`stats count by TargetUserName`)
4. Pivot ([pivots](../queries/README.md)): what did `svc_backdoor` do after creation?
   (4624 logons, further group changes, PowerShell — correlate.)
5. Contain: disable the account, remove it from admin groups, force a password reset for
   the `SubjectUserName` admin account (it is compromised!).
6. Report: persistence + privilege escalation in one incident = High/Critical.

## 5. Response & Cleanup

```cmd
:: Eradicate the persistence
net group "Domain Admins" svc_backdoor /delete /domain
net localgroup administrators svc_backdoor /delete
net user svc_backdoor /delete /domain
```

- [ ] Verify removal (`net group "Domain Admins" /domain` shows no `svc_backdoor`)
- [ ] Screenshot cleanup confirmation for the evidence set

## 6. Evidence Checklist

- [ ] `08a_account_commands.png`
- [ ] `08b_event_4720_4728.png`
- [ ] `08_splunk_alert_account.png`

## 7. Lessons / Tuning Notes *(fill after execution)*

- Why is `4728` (Domain Admins) higher severity than `4732` (local admins)? (scope of access — put your answer in the report)
- What extra signal would you add to cut false positives from legitimate provisioning?
  (e.g. correlate with a change-management system, or alert only outside business hours / outside IT admin accounts)
