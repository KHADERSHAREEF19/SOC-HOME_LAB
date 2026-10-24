# SIM-05 — Defense Evasion: Log Clearing & Agent Tampering ⚠️ run last

| | |
|---|---|
| **ID** | SIM-05 |
| **ATT&CK** | T1070.001 Indicator Removal: Clear Windows Event Logs · T1562.001 Impair Defenses: Disable or Modify Tools |
| **Tactic** | Defense Evasion |
| **Attacker** | Simulated foothold on `192.168.1.11` (local admin `testuser`) |
| **Target** | Windows 11 `192.168.1.11` + its Wazuh agent |
| **Detection rules** | `100120` (wevtutil clear) · built-in Windows 1102 rule · built-in agent-disconnect alert |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Emulate the moment a real actor tries to **cover their tracks**: clearing the Security log
and stopping the monitoring agent. Two lessons drive this simulation:

1. **Log clearing leaves its own loud evidence** (Event 1102 + Sysmon) — a gift to defenders.
2. **Agent tampering creates a telemetry gap**, and *the gap itself is evidence*.

> ⚠️ **Order matters:** run this *after* SIM-01–04, since clearing the Security log erases
> prior raw events (Wazuh retains what it already ingested — that retention is itself
> a talking point for your report).

## Scope & Safety

- Both actions run only on `192.168.1.11`.
- The agent is restarted in the cleanup phase so the lab returns to full monitoring.

## Prerequisites

- [ ] SIM-01–04 executed and evidence captured (this sim destroys raw local logs!)
- [ ] Rules `100120` + Windows 1102 detection active
- [ ] You know how to restart the Wazuh agent service

---

## 1. Attack Execution

### Phase A — Clear the Windows Security log

```cmd
wevtutil cl Security
```

Variants actors use (worth one line each in your notes):

```cmd
wevtutil sl Security /e:false     # disable logging first, then operate
wevtutil cl System
wevtutil cl "Windows PowerShell"
```

### Phase B — Stop the monitoring agent

```cmd
NET STOP WazuhSvc
```

📸 Screenshot: `screenshots/09a_wevtutil_clear.png` — terminal + confirmation output.

## 2. Expected Telemetry

| Action | Source | Event | Why it matters |
|--------|--------|-------|----------------|
| Log cleared | Windows Security **1102** (written to the *new* empty log) | "The audit log was cleared" | Names the clearing account & time — survives the wipe |
| `wevtutil` executed | Sysmon **EID 1** → rule **`100120`** | alert | Command line proves intent (`cl Security`) |
| Agent stopped | Wazuh **agent disconnect** (manager-side) | monitoring gap | Absence of events = evidence |
| Event volume | Dashboard | sudden drop to zero for `WIN11-PRO` | The "gap window" for your report |

📸 Screenshots:
- `screenshots/09_event_1102_log_cleared.png` — Event 1102 in Event Viewer / Wazuh
- `screenshots/09b_agent_disconnected.png` — Wazuh Agents page showing disconnect

## 3. Detection

Queries (see [`../queries/defense-evasion.md`](../queries/defense-evasion.md)):

```
rule.id : 100120
```

```
data.win.system.eventID : 1102
```

```
agent.name : WIN11-PRO    # look for the gap in the event histogram
```

## 4. Triage Walkthrough

1. Open the 1102 event → **note the account name** — that account is hostile until proven otherwise.
2. Ask the critical question: *what did the attacker do before wiping the logs?*
   Pivot to Wazuh (it retains ingested events even after the source log is cleared):

   ```
   agent.name : WIN11-PRO AND rule.groups : (brute_force or persistence or windows_powershell)
   ```

3. Define the **gap window** (agent stop → restart) and state it explicitly in the report.
4. Correlate: 1102 + agent stop within minutes of each other = deliberate anti-forensics,
   almost never an accident. Raise severity.
5. Contain: re-enable logging, restart the agent, isolate the host if still live.

## 5. Response & Cleanup (mandatory)

```cmd
# Re-enable and restart monitoring
wevtutil sl Security /e:true
NET START WazuhSvc
```

- [ ] Agent shows **Active** in the dashboard again
- [ ] New test events flow (`whoami` produces fresh Sysmon EID 1)
- [ ] Gap window timestamps recorded in the report

## 6. Evidence Checklist

- [ ] `09a_wevtutil_clear.png`
- [ ] `09_event_1102_log_cleared.png`
- [ ] `09b_agent_disconnected.png`

## 7. Lessons / Tuning Notes *(fill after execution)*

- Why doesn't clearing the log erase Wazuh's copy? (forwarded vs local retention — explain it)
- What production control detects agent tampering *even when the agent can't report it*?
  (e.g. manager-side heartbeat alerting, redundant log shipping — put your answer in the report)
