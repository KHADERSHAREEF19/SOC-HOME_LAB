# SIM-05 — Defense Evasion: Audit Log Wipe & Forwarder Tampering ⚠️ run last

| | |
|---|---|
| **ID** | SIM-05 |
| **ATT&CK** | T1070.001 Indicator Removal: Clear Windows Event Logs · T1562.001 Impair Defenses: Disable or Modify Tools |
| **Tactic** | Defense Evasion |
| **Attacker** | Simulated foothold on the DC `192.168.1.11` (local admin) |
| **Target** | Windows Server 2022 DC `192.168.1.11` + its Splunk Universal Forwarder |
| **Detection** | Saved search **"Defense Evasion - Audit Log Cleared 1102"** → [`queries/05-log-wipe.spl`](../queries/05-log-wipe.spl) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Emulate the moment a real actor tries to **cover their tracks**: wiping the audit log and
stopping the telemetry forwarder. Two lessons drive this simulation:

1. **Log clearing leaves its own loud evidence** (Event 1102) — a gift to defenders.
   The event is written *after* the wipe, so it survives the clearing, and it **names the
   account that did it**.
2. **Forwarder tampering creates a telemetry gap**, and *the gap itself is evidence*.

> ⚠️ **Order matters:** run this *after* SIM-01–04, since clearing the Security log erases
> prior raw local events. Splunk's index retains everything already forwarded — that
> retention difference (local log vs indexed data) is itself a great report talking point.

## Scope & Safety

- Both actions run only on `192.168.1.11`.
- The forwarder is restarted in the cleanup phase so the lab returns to full monitoring.

## Prerequisites

- [ ] SIM-01–04 executed and evidence captured (this sim destroys raw local logs!)
- [ ] Splunk time range set; you know how to restart the Universal Forwarder service

---

## 1. Attack Execution

### Phase A — Wipe the Windows audit log

```cmd
wevtutil cl Security
```

Variants actors use (worth one line each in your notes):

```cmd
wevtutil sl Security /e:false     # disable logging first, then operate
wevtutil cl System
wevtutil cl "Windows PowerShell"
```

### Phase B — Stop the telemetry forwarder

```cmd
NET STOP SplunkForwarder
```

📸 Screenshot: `screenshots/09a_wevtutil_clear.png` — terminal + confirmation output.

## 2. Expected Telemetry

| Action | Source | EventCode | Why it matters |
|--------|--------|-----------|----------------|
| Log wiped | `WinEventLog:Security` | **1102** | Written to the *new* empty log — survives the wipe, names the account |
| Forwarder stopped | `WinEventLog:System` | **7036** (service state change) | "The Splunk Forwarder Service service entered the stopped state" — visible *if* it shipped before the gap |
| Detection | Saved search **Defense Evasion - Audit Log Cleared 1102** | — | `Account_Name`, `Domain_Name`, `Log_Name` |
| Event volume | Splunk | sudden drop to zero for `WIN-DC01` | The "gap window" for your report |

📸 Screenshots:
- `screenshots/09_event_1102_log_cleared.png` — SPL results / Triggered Alert for EventCode 1102
- `screenshots/09b_forwarder_stopped.png` — `splunk list forward-server` / service stopped + the event-volume drop in Splunk

## 3. Detection (SPL)

Run in Splunk Web (raw file: [`05-log-wipe.spl`](../queries/05-log-wipe.spl)):

```spl
index=main sourcetype="WinEventLog:Security" EventCode=1102
| table _time, host, Account_Name, Domain_Name, Log_Name
```

Forwarder tamper pivot (System channel):

```spl
index=main sourcetype="WinEventLog:System" EventCode=7036 host="WIN-DC01"
| search Message="*Splunk*"
| table _time, host, Message
```

## 4. Triage Walkthrough

1. Open the 1102 event → **note `Account_Name`** — that account is hostile until proven otherwise.
2. Ask the critical question: *what did the attacker do before wiping the logs?*
   Pivot to the Splunk index (indexed data survives the local wipe):

   ```spl
   index=main host="WIN-DC01" earliest=-24h
   | search (EventCode=4625 OR EventCode=4624 OR EventCode=4720 OR EventCode=1) NOT EventCode=1102
   | table _time, EventCode, Account_Name, CommandLine
   | sort _time
   ```

3. Define the **gap window** (forwarder stop → restart) from the event-volume drop and
   state it explicitly in the report.
4. Correlate: 1102 + forwarder stop within minutes of each other = deliberate anti-forensics,
   almost never an accident. Raise severity to Critical.
5. Contain: re-enable logging, restart the forwarder, isolate the host if still live.

## 5. Response & Cleanup (mandatory)

```cmd
:: Re-enable and restart monitoring
wevtutil sl Security /e:true
NET START SplunkForwarder
```

- [ ] Forwarder shows in `splunk list forward-server`; events flow again (test with `whoami`)
- [ ] New events indexed after the gap start time
- [ ] Gap window timestamps recorded in the report

## 6. Evidence Checklist

- [ ] `09a_wevtutil_clear.png`
- [ ] `09_event_1102_log_cleared.png`
- [ ] `09b_forwarder_stopped.png`

## 7. Lessons / Tuning Notes *(fill after execution)*

- Why doesn't clearing the local log erase Splunk's copy? (forwarded/indexed vs local
  retention — explain it in one sentence for your report)
- What production control detects forwarder tampering *even when the forwarder can't report it*?
  (e.g. index-time volume anomaly alerting, redundant forwarders, host-based service
  monitoring — put your answer in the report)
