# 🎯 Adversary Simulation Plan

This folder contains the attack simulations that power this lab. Each runbook follows the
**same repeatable structure** so a reviewer can see the full detection loop:

```
Objective → Attack execution (real commands) → Expected telemetry (Windows Event IDs) →
Detection (SPL / saved search) → Triage walkthrough → Response & cleanup → Evidence checklist
```

All detection content is **Splunk SPL** — runnable searches in [`../queries/*.spl`](../queries/)
and scheduled alerts in [`../configs/savedsearches.conf`](../configs/savedsearches.conf).

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

| ID | Runbook | ATT&CK | Tactic | Key telemetry (EventCode) | Detection SPL |
|----|---------|--------|--------|---------------------------|---------------|
| SIM-01 | [AD Enumeration & Network Discovery](SIM-01-ad-enumeration.md) | T1087.002, T1069.002, T1046 | Discovery | Security 4662/4661 | [`01-ad-enumeration.spl`](../queries/01-ad-enumeration.spl) |
| SIM-02 | [Brute Force → Valid Account](SIM-02-brute-force.md) | T1110.001, T1078 | Credential Access | Security 4625 → 4624 | [`02-brute-force.spl`](../queries/02-brute-force.spl) |
| SIM-03 | [Suspicious PowerShell](SIM-03-suspicious-powershell.md) | T1059.001, T1105 | Execution | Sysmon 1 | [`03-powershell-execution.spl`](../queries/03-powershell-execution.spl) |
| SIM-04 | [Account Creation & Group Elevation](SIM-04-account-persistence.md) | T1136.001, T1098 | Persistence | Security 4720/4732/4728 | [`04-account-persistence.spl`](../queries/04-account-persistence.spl) |
| SIM-05 | [Defense Evasion: Audit Log Wipe & Agent Tamper](SIM-05-defense-evasion.md) | T1070.001, T1562.001 | Defense Evasion | Security 1102 (+ System 7036) | [`05-log-wipe.spl`](../queries/05-log-wipe.spl) |
| SIM-06 | [Malware Delivery: EICAR](SIM-06-malware-delivery.md) | T1204.002, T1105 | Execution | Sysmon 11 | [`06-eicar-file-create.spl`](../queries/06-eicar-file-create.spl) |

**Execution order:** SIM-01 → SIM-02 first (they set up the "attacker has been here"
narrative), then 03–06 in any order. SIM-05 runs **last** since it disrupts logging.

## Per-simulation definition of "done"

A simulation is only complete when **all five** exist:

1. ✅ Attack command executed from `192.168.1.8` (screenshot in `screenshots/`)
2. ✅ Telemetry observed in **Splunk Web** (`http://192.168.1.25:8000`) (screenshot)
3. ✅ The saved search in [`../configs/savedsearches.conf`](../configs/savedsearches.conf) fired
   (Triggered Alerts) — or a documented decision to tune it
4. ✅ Triage performed with the pivots in [`../queries/README.md`](../queries/README.md)
5. ✅ An incident report entry — at minimum SIM-02 gets a full report
   ([`../incident-reports/IR-2026-001-brute-force.md`](../incident-reports/IR-2026-001-brute-force.md))

## 🔒 Safety & authorization rules (non-negotiable)

- All targets are **VMs in this lab only** (`192.168.1.11`, the lab's own Domain Controller).
  Never point these commands at any system you do not own and have explicit written
  permission to test.
- The lab runs on an **isolated internal virtual network** (Host-Only / Internal adapter)
  with the host OS fully segregated; no attack traffic leaves the lab subnet.
- Use **harmless stand-ins** wherever possible: `testuser`/`svc_backdoor` accounts,
  the EICAR test file instead of real malware, benign payload text files.
- Clean up after each run (delete accounts/groups/files, re-enable logging) — documented in
  each runbook's **Response & Cleanup** section.
- These materials exist to teach **defenders** how to detect this activity.

## Screenshot naming for simulations

See [`../screenshots/README.md`](../screenshots/README.md). Short version:

```
screenshots/04_hydra_bruteforce.png        ← attack executing (Kali terminal)
screenshots/05_event_4625_spike.png        ← raw telemetry / SPL results
screenshots/06_splunk_alert_bruteforce.png ← Splunk saved search / alert firing
```

One idea per screenshot, timestamps visible, terminal and SPL fonts readable.
