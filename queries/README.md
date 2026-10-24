# 🔍 SPL Detection & Investigation Queries

Production-ready **SPL (Search Processing Language)** for Splunk Enterprise.
Every file here is a runnable search against the lab's `main` index and maps
1:1 to a saved alert in [`../configs/savedsearches.conf`](../configs/savedsearches.conf)
and a simulation in [`../simulations/`](../simulations/).

## Query index

| File | Simulation | ATT&CK | What it finds |
|------|-----------|--------|---------------|
| [`01-ad-enumeration.spl`](01-ad-enumeration.spl) | SIM-01 | T1087.002 · T1069.002 | AD object access enumeration (4662/4661) |
| [`02-brute-force.spl`](02-brute-force.spl) | SIM-02 | T1110.001 · T1078 | Brute force + confirmed compromise (4625/4624) |
| [`03-powershell-execution.spl`](03-powershell-execution.spl) | SIM-03 | T1059.001 · T1105 | Suspicious PowerShell (Sysmon EID 1) |
| [`04-account-persistence.spl`](04-account-persistence.spl) | SIM-04 | T1136.001 · T1098 | Account creation & group elevation (4720/4732/4728) |
| [`05-log-wipe.spl`](05-log-wipe.spl) | SIM-05 | T1070.001 | Audit log cleared (1102) |
| [`06-eicar-file-create.spl`](06-eicar-file-create.spl) | SIM-06 | T1204.002 · T1105 | EICAR test-file write (Sysmon EID 11) |

## How to run them

1. Open **Splunk Web** at `http://192.168.1.25:8000` (from the Kali machine's browser).
2. **Apps → Search & Reporting** → set the time range to your simulation window.
3. Paste the SPL from any file above → **Search**.
4. Save results as screenshots per [`../screenshots/README.md`](../screenshots/README.md).

> **Field names in this repo:** `EventCode`, `Account_Name`, `Source_Network_Address`,
> `Image`, `CommandLine`, `ParentCommandLine`, `TargetFilename`, `TargetUserName`,
> `MemberName`, `SubjectUserName`, `User`, `Log_Name`, `Domain_Name`.
> Confirm any of them against a real event (**event → XML tab**) before relying on it —
> depending on the Windows TA and `props.conf`, some values sit under `EventData.*`.

## Investigation pivots (triage-time SPL)

Run these when an alert fires — they turn "an alert" into "an incident report".

### Brute force (SIM-02) — scope the attack

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) Source_Network_Address="192.168.1.8"
| stats count by EventCode, Account_Name, TargetLogonType
| sort - _time
```

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624 Source_Network_Address="192.168.1.8"
| table _time, Account_Name, TargetLogonType, Logon_Process
```

### AD enumeration (SIM-01) — who queried what?

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4662 OR EventCode=4661) Account_Name!="*$"
| stats count values(Object_Type) as Objects by Account_Name, Source_Network_Address
| sort - count
```

### PowerShell (SIM-03) — rebuild the process tree

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host="WIN-DC01"
| table _time, User, ParentImage, Image, CommandLine, ParentCommandLine
| sort _time
```

### Account persistence (SIM-04) — the new account's story

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4724 OR EventCode=4732 OR EventCode=4728) TargetUserName="*"
| table _time, EventCode, TargetUserName, MemberName, SubjectUserName
| sort _time
```

### Log wipe (SIM-05) — what happened before the wipe?

```spl
index=main sourcetype="WinEventLog:Security" EventCode=1102
| fields _time, Account_Name
```

```spl
index=main host="WIN-DC01" earliest=-24h
| search (EventCode=4625 OR EventCode=4624 OR EventCode=4720 OR EventCode=1) NOT EventCode=1102
| table _time, EventCode, Account_Name, CommandLine
| sort _time
```

> **Golden rule (same as any SIEM):** the *absence* of logs never proves the *absence*
> of activity. After a 1102, always report the visibility gap explicitly.

### EICAR (SIM-06) — delivery chain

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=11 OR EventCode=3) host="WIN-DC01"
| table _time, EventCode, Image, TargetFilename, DestinationIp
| sort _time
```

## Building the SOC dashboard (for screenshots)

In **Splunk Web → Dashboards → Create New Dashboard**, add four panels:

| Panel | Search | Proves |
|-------|--------|--------|
| Failed vs successful logons over time | `index=main EventCode=4625 OR EventCode=4624 \| timechart count(eval(EventCode=4625)) as Failed, count(eval(EventCode=4624)) as Success` | The 4625 spike during the attack |
| Top source IPs by failed logons | `index=main EventCode=4625 \| top Source_Network_Address` | Attribution to `192.168.1.8` |
| Alert table | `index=main alert \| table _time, search_name, savedsearch_name` | Detection firing |
| Sysmon process activity | `index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 \| top Image` | Execution visibility |
