# Persistence — Scheduled Task & Run-Key Autorun (SIM-04)

**ATT&CK:** T1053.005 (Scheduled Task) · T1547.001 (Registry Run Keys)
**Events:** Security 4698 (task created) · Sysmon EID 1 (`schtasks`) · Sysmon EID 13 (registry value set)
**Custom rules:** `100130`, `100135`

---

## 1. Detection query — custom rules fired?

```
rule.id : (100130 or 100135)
```

## 2. Scheduled task telemetry

```
data.win.system.eventID : 4698
```

```
data.win.eventdata.commandLine : *schtasks* /create*
```

Fields that matter for triage:

| Field | Question it answers |
|-------|---------------------|
| Task name (`data.win.eventdata.taskName`) | What did the attacker name it? (malware loves "Update", "OneDrive", "svchost") |
| Task content / action | What does it execute when it runs? |
| Creator user (`data.win.eventdata.subjectUserName`) | Which account created it — and did it have admin rights? |
| Trigger (time / logon) | When will it fire again? |

## 3. Registry autorun telemetry

```
data.win.eventdata.targetObject : *CurrentVersion*Run*
```

```
data.win.system.eventID : 13 AND data.win.eventdata.targetObject : *Run*
```

Expected evidence: the `Run` key name plus `details` (the executable path it points to).
Cross-check the path with Sysmon file-create events — did the payload actually exist there?

## 4. Scoping — is this normal software or attacker tooling?

```
data.win.eventdata.targetFilename : *<suspicious path from the Run value>*
```

```
agent.name : WIN11-PRO AND data.win.system.eventID : (4698 or 13)
```

**Triage questions (use these verbatim in your incident report):**

1. Is the task/Run key a known-good IT deployment? (check naming, path, signer)
2. Does the referenced binary exist? Unsigned or in a user-writable path = red flag.
3. Was it created interactively (console logon) or remotely? (logon type of the creating session)
4. What else did this account do in the same hour? (pivot to discovery / execution queries)

## 5. Cleanup evidence (document it!)

After the report: remove the scheduled task / Run key and show the cleanup command in
your notes. Recruiters love seeing the **full lifecycle**: detect → report → eradicate.
