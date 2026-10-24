# SIM-04 — Persistence: Scheduled Task & Run Key

| | |
|---|---|
| **ID** | SIM-04 |
| **ATT&CK** | T1053.005 Scheduled Task/Job: Scheduled Task · T1547.001 Boot or Logon Autostart: Registry Run Keys |
| **Tactic** | Persistence |
| **Attacker** | Simulated foothold on `192.168.1.11` (commands run from Kali over WinRM, or locally as `testuser`) |
| **Target** | Windows 11 `192.168.1.11` |
| **Detection rules** | `100130` (schtasks create) · `100135` (Run-key autorun) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Install two classic Windows persistence mechanisms a real actor would leave behind, and
detect **both** from telemetry: a scheduled task that runs a benign payload, and a
registry `Run` key pointing at it. Persistence detection is a staple SOC skill —
"what survives the reboot?" is a question interviewers love.

## Scope & Safety

- Payload: `C:\Users\testuser\lab\persist.bat` containing only `echo lab persistence marker`.
- Everything is deleted in the cleanup phase — no real backdoors.

## Prerequisites

- [ ] Sysmon EID 1 + 13 active; Security auditing for 4698 enabled
- [ ] Rules `100130` / `100135` installed
- [ ] `testuser` local admin (needed for `schtasks /create` as SYSTEM-style task)

---

## 1. Attack Execution

### Phase A — Stage the benign payload

```powershell
mkdir C:\Users\testuser\lab
Set-Content C:\Users\testuser\lab\persist.bat 'echo lab persistence marker'
```

### Phase B — Scheduled task persistence

```cmd
schtasks /create /tn "OneDriveUpdate" /tr "C:\Users\testuser\lab\persist.bat" /sc onlogon /ru SYSTEM /f
schtasks /run /tn "OneDriveUpdate"
```

(Attacker-style naming — "OneDriveUpdate" — is deliberate; discuss masquerading in your notes.)

### Phase C — Registry Run-key persistence

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveUpdate" /t REG_SZ /d "C:\Users\testuser\lab\persist.bat" /f
```

📸 Screenshot: `screenshots/08a_persistence_commands.png` — the two commands + confirmation.

## 2. Expected Telemetry

| Action | Source | Event | Evidence fields |
|--------|--------|-------|-----------------|
| Task created | Security **4698** | Scheduled task created | task name, content, creating user |
| `schtasks` runs | Sysmon **EID 1** → rule **`100130`** | alert | `commandLine` contains `/create` |
| Run key set | Sysmon **EID 13** → rule **`100135`** | alert | `targetObject` = `...\CurrentVersion\Run\...`, `details` = payload path |
| Task fires | Sysmon EID 1 | `persist.bat` → `cmd.exe` | proves the mechanism works |

📸 Screenshots:
- `screenshots/08b_event_4698.png` — Security event 4698 (or Sysmon 13) in Event Viewer
- `screenshots/08_persistence_alert.png` — Wazuh `100130` / `100135` firing

## 3. Detection

Queries (see [`../queries/persistence.md`](../queries/persistence.md)):

```
rule.id : (100130 or 100135)
```

```
data.win.system.eventID : 4698
```

```
data.win.eventdata.targetObject : *CurrentVersion*Run*
```

## 4. Triage Walkthrough

1. Collect: task name, trigger, action/author, creating account; Run-key value path.
2. Reputation check: is "OneDriveUpdate" in a legitimate OneDrive path? (No → red flag.)
3. Does the payload exist? Is it signed? (`persist.bat` in a user profile = obvious.)
4. Pivot: what created the file? (Sysmon EID 11 near the same time) — rebuild the actor's steps.
5. Scope: any other tasks/autoruns created that day? (`4698` + EID 13 across the window).
6. Contain: disable the task + delete the Run key + quarantine the file; then hunt persistence on sibling hosts.

## 5. Response & Cleanup

```cmd
schtasks /delete /tn "OneDriveUpdate" /f
```

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveUpdate"
Remove-Item -Recurse C:\Users\testuser\lab
```

- [ ] Reboot (or at least re-logon) and confirm nothing re-appears
- [ ] Screenshot cleanup confirmation for the evidence set

## 6. Evidence Checklist

- [ ] `08a_persistence_commands.png`
- [ ] `08b_event_4698.png`
- [ ] `08_persistence_alert.png`

## 7. Lessons / Tuning Notes *(fill after execution)*

- Which of the two mechanisms was *noisier* in telemetry? (Usually the task — note why.)
- Why do real actors prefer tasks over Run keys for enterprise estates? (SYSTEM context,
  triggers, no user logon needed — put your answer in the report.)
