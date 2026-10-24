# Execution — Suspicious PowerShell & Malware Delivery (SIM-03, SIM-06)

**ATT&CK:** T1059.001 (PowerShell) · T1105 (Ingress Tool Transfer) · T1204.002 (Malicious File)
**Events:** Sysmon EID 1 (process) · Sysmon EID 11 (file create) · PowerShell 4104 · Defender 1116/1117
**Custom rules:** `100110`, `100145`

---

## 1. Detection query — custom rule fired?

```
rule.id : (100110 or 100145)
```

## 2. Raw telemetry — all PowerShell activity in the window

```
data.win.eventdata.image : *powershell* AND agent.name : WIN11-PRO
```

Suspicious indicators to look for in `data.win.eventdata.commandLine`:

| Indicator | Why it matters | ATT&CK |
|-----------|----------------|--------|
| `-enc` / `-EncodedCommand` | Hides intent in base64 | T1059.001, T1140 |
| `downloadstring`, `Invoke-WebRequest`, `IEX` | Download cradle → second-stage payload | T1105 |
| `-WindowStyle Hidden`, `-nop` | User-invisible execution | T1059.001 |
| `FromBase64String` | Payload decoding | T1140 |

## 3. Reconstruct the command (evidence for the report)

Open the matched event → JSON tab → copy:

- `data.win.eventdata.commandLine` (what was run)
- `data.win.eventdata.parentImage` (what launched it — e.g. `cmd.exe` vs `WINWORD.EXE`)
- `data.win.eventdata.user` (which account)

> **Triage question:** is the parent process expected? `winword.exe → powershell.exe`
> (macro) is far worse than `explorer.exe → powershell.exe` (user opened a terminal).

## 4. Malware delivery (SIM-06)

```
data.win.eventdata.targetFilename : *eicar*
```

```
rule.id : 100145 OR rule.groups : windows_defender
```

```
data.win.system.eventID : (1116 or 1117)
```

Expected chain: file lands on disk (Sysmon 11) → Defender detects (1116) → action taken (1117).
This is a perfect demonstration of **multi-sensor correlation**: even if one control is
missed, the other two still tell the story.

## 5. Scoping — did anything else execute around that time?

```
agent.name : WIN11-PRO AND data.win.eventdata.parentImage : *powershell*
```

Build the **process tree** (parent → child) in your notes — it is the core of any real
malware triage and impresses in interviews.
