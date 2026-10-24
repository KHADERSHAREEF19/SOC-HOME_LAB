# 🎯 Adversary Simulation Plan

This folder contains the attack simulations that power this lab. Each runbook follows the
**same repeatable structure** so a reviewer can see the full detection loop:

```
Objective → Attack execution (real commands) → Expected telemetry →
Detection (rule + query) → Triage walkthrough → Response & cleanup → Evidence checklist
```

## How many simulations? (the recruiter's answer)

**Six fully documented simulations is the sweet spot** for a SOC Analyst portfolio:

| Count | How it reads to a recruiter |
|-------|----------------------------|
| 1–3 | "They followed one tutorial." |
| **4–6** | **"They understand the kill chain and can document it."** ← aim here |
| 7–10 | Only if every one has full evidence — otherwise it looks like checkbox collecting |
| 15+ shallow | Red flag: breadth without depth, usually copied commands |

The right six (chosen below) cover **one simulation per major ATT&CK tactic**, ending with
at least one **full incident report** — that combination mirrors an actual Tier-1 workload
(alert in queue → investigate → ticket → escalate).

## Simulation matrix

| ID | Runbook | ATT&CK | Tactic | Key telemetry | Docs complete |
|----|---------|--------|--------|---------------|---------------|
| SIM-01 | [Network & Host Discovery](SIM-01-network-host-discovery.md) | T1046, T1082, T1087 | Discovery | Sysmon EID 1 cluster + gap analysis | ☐ |
| SIM-02 | [Brute Force → Valid Account](SIM-02-brute-force.md) | T1110.001, T1078 | Credential Access | 4625 → 4624 | ☐ |
| SIM-03 | [Suspicious PowerShell](SIM-03-suspicious-powershell.md) | T1059.001, T1105 | Execution | Sysmon EID 1, PS 4104 | ☐ |
| SIM-04 | [Persistence: Task & Run Key](SIM-04-persistence.md) | T1053.005, T1547.001 | Persistence | 4698, Sysmon EID 1/13 | ☐ |
| SIM-05 | [Defense Evasion: Log Clear + Agent Tamper](SIM-05-defense-evasion.md) | T1070.001, T1562.001 | Defense Evasion | 1102, agent gap | ☐ |
| SIM-06 | [Malware Delivery: EICAR](SIM-06-malware-delivery.md) | T1204.002, T1105 | Execution | Defender 1116/1117, Sysmon EID 11 | ☐ |

**Execution order:** run SIM-01 → SIM-02 first (they set up the "attacker has been here"
narrative), then 03–06 in any order. SIM-05 runs **last** since it disrupts logging.

## Per-simulation definition of "done"

A simulation is only complete when **all five** exist:

1. ✅ Attack command executed from `192.168.1.8` (screenshot in `screenshots/`)
2. ✅ Telemetry observed in the Wazuh dashboard / Event Viewer (screenshot)
3. ✅ Custom rule fired — or a documented decision to tune one (rule ID noted)
4. ✅ Triage performed using the queries in [`../queries/`](../queries/)
5. ✅ An incident report entry — at minimum SIM-02 gets a full report
   ([`../incident-reports/IR-2026-001-brute-force.md`](../incident-reports/IR-2026-001-brute-force.md))

## 🔒 Safety & authorization rules (non-negotiable)

- All targets are **VMs in this lab only** (`192.168.1.11`). Never point these commands
  at any system you do not own and have explicit written permission to test.
- The lab runs on a **host-only network** with no internet path during attack windows.
- Use **harmless stand-ins** wherever possible: `testuser` account, EICAR file instead of
  real malware, `calc.exe` as a benign payload, simulation web servers on the lab subnet.
- Clean up after each run (delete tasks/keys/files, re-enable logging) — documented in
  each runbook's **Response & Cleanup** section.
- These materials exist to teach **defenders** how to detect this activity.

## Screenshot naming for simulations

See [`../screenshots/README.md`](../screenshots/README.md). Short version:

```
screenshots/04_hydra_bruteforce.png        ← attack executing
screenshots/05_event_4625_spike.png        ← raw telemetry
screenshots/06_wazuh_alert_bruteforce.png  ← SIEM detection
```

One idea per screenshot, timestamps visible, terminal fonts readable.
