# Defense Evasion — Log Clearing & Agent Tampering (SIM-05)

**ATT&CK:** T1070.001 (Clear Windows Event Logs) · T1562.001 (Impair Defenses: Disable Tools)
**Events:** Security 1102 (audit log cleared) · Sysmon EID 1 (`wevtutil`) · Wazuh agent status
**Custom rules:** `100120`

---

## 1. Detection query — custom rule fired?

```
rule.id : 100120
```

## 2. The smoking gun — Event ID 1102

```
data.win.system.eventID : 1102
```

Event 1102 is generated **the moment the Security log is cleared** and names the account
that did it. This single event is one of the strongest "insider/hostile actor" signals a
SOC can receive — and it survives the log clearing (it is written to the *new* empty log).

| Field | Why it matters |
|-------|----------------|
| SubjectUserName / SID | WHO cleared the log → the account to disable first |
| timestamp | WHEN — compare with your last known-good event before the gap |

## 3. Process context (Sysmon)

```
data.win.eventdata.image : *wevtutil*
```

```
data.win.eventdata.commandLine : *cl*
```

Even after the log is cleared, **Sysmon's own channel** retains the `wevtutil` process
creation — two independent sensors telling the same story. This is exactly why defense
in depth on the endpoint matters, and it's a great interview talking point.

## 4. Agent tampering (monitoring gap alert)

If the attacker stops the Wazuh agent (`NET STOP WazuhSvc`), expect:

- Manager-side rule "Wazuh agent disconnected" (built-in) in **Management → Agents**.
- A **gap** in that host's events — the absence of telemetry is itself evidence.

Query for the gap window:

```
agent.name : WIN11-PRO
```

Compare event counts before/after the agent stop; put the gap start/end times in the report.

## 5. Scoping — what did the attacker do BEFORE wiping the logs?

Log clearing is almost always post-exploitation cleanup. Pivot immediately:

```
agent.name : WIN11-PRO AND rule.groups : (brute_force or persistence or windows_powershell)
```

> **Golden triage rule:** the *absence* of logs never means the *absence* of activity.
> Report the visibility gap explicitly — never write "no further activity found" without
> stating that the audit log was cleared between X and Y.
