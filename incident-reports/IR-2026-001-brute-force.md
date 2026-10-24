# Incident Report — IR-2026-001: Brute-Force Attack Followed by Valid Account Use

> ⚠️ **PLACEHOLDER EXAMPLE — format showcase.** The structure, analysis style and
> escalation language below show the *target quality* for a completed report.
> All timestamps, counts and alert IDs are **illustrative placeholders** (marked `⟨…⟩`).
> When SIM-02 is executed, replace them with real captured data before presenting
> this repository as executed work.

| Field | Value |
|-------|-------|
| **Report ID** | IR-2026-001 |
| **Title** | Brute-force password attack against `WIN11-PRO` with confirmed successful logon |
| **Severity** | 🔴 **Critical** — valid credential compromised (rule `100102`) |
| **Status** | Contained → Closed (lab) |
| **Category** | Credential Access — T1110.001 / T1078 |
| **Related simulation** | [SIM-02](../simulations/SIM-02-brute-force.md) |
| **Analyst** | Khader Shareef Madani (Tier 1 — triage & documentation) |
| **Date opened** | ⟨2026-10-24 12:38 UTC+05:30⟩ |
| **Date closed** | ⟨2026-10-24 13:05 UTC+05:30⟩ |

## 1. Summary

The Wazuh SIEM raised a **level-12 brute-force alert** (rule `100101`) after ⟨N⟩ failed
interactive/network logons against the local account `testuser` on `WIN11-PRO`, all
originating from `192.168.1.8` (lab adversary node "Kali"). Within ⟨minutes⟩ of the burst
a **successful logon (4624)** from the same source triggered rule `100102`, indicating
the attacker **validly authenticated** with the guessed password. The account was
disabled and the source IP blocked at the host firewall at ⟨time⟩. Full simulation
documentation: [SIM-02](../simulations/SIM-02-brute-force.md).

## 2. Affected Assets & Accounts

| Type | Value | Role |
|------|-------|------|
| Host | `WIN11-PRO` (`192.168.1.11`) | Lab user endpoint (Windows 11 Enterprise) |
| Account | `testuser` (local, non-admin — *verify after execution*) | Targeted account |
| Source IP | `192.168.1.8` | Lab adversary node (Kali Linux) |

## 3. Timeline (UTC+05:30)

| Time | Event | Source |
|------|-------|--------|
| ⟨12:31:02⟩ | First failed logon — 4625, `testuser`, from `192.168.1.8`, logon type ⟨3⟩ | Security log via Wazuh |
| ⟨12:31:02–12:33:41⟩ | ⟨N⟩ failed logons (4625) from `192.168.1.8` | Rule `100100` base events |
| ⟨12:33:42⟩ | **Rule `100101` fired** — brute-force burst (≥8 fails / 120 s / same IP) | Wazuh alert |
| ⟨12:34:17⟩ | Successful logon (4624), `testuser`, from `192.168.1.8`, logon type ⟨3⟩ | Security log |
| ⟨12:34:18⟩ | **Rule `100102` fired** — CRITICAL: success after brute force | Wazuh alert |
| ⟨12:38:00⟩ | Triage started; queries executed ([§4](#4-observations--evidence)) | Analyst |
| ⟨12:47:30⟩ | Containment: `testuser` disabled; firewall rule blocking `192.168.1.8` | Analyst |
| ⟨13:05:00⟩ | Report completed; escalated to Tier 2 for review | Analyst |

## 4. Observations & Evidence

### 4.1 Detection

- **Alerts:** `100101` (level 12) → `100102` (level 14)
- **Queries used** ([full set](../queries/credential-access.md)):

  ```
  rule.id : (100101 or 100102)
  ```

  ```
  data.win.system.eventID : (4625 or 4624) AND data.win.eventdata.ipAddress : 192.168.1.8
  ```

- **Key fields observed:**

  | Field | Value |
  |-------|-------|
  | `data.win.eventdata.targetUserName` | `testuser` |
  | `data.win.eventdata.ipAddress` | `192.168.1.8` |
  | `data.win.eventdata.logonType` | ⟨3 (network / SMB)⟩ |
  | Failed/successful counts | ⟨N failed · 1 successful⟩ |
  | Window | ⟨12:31:02 – 12:34:17⟩ |

### 4.2 Evidence screenshots

| # | File | Shows |
|---|------|-------|
| 1 | `screenshots/04_hydra_bruteforce.png` | Attack execution (Hydra against `192.168.1.11`) |
| 2 | `screenshots/05_event_4625_spike.png` | 4625 spike in raw telemetry |
| 3 | `screenshots/06_wazuh_alert_bruteforce.png` | Rules `100101` / `100102` on the dashboard |

### 4.3 Analysis

The volume, pacing and single-source/single-account pattern match an **automated password
guessing tool** (consistent with the lab's Hydra execution), not a user mistyping a password
(typo patterns: 1–3 attempts, multiple accounts, business-hours timing). The subsequent
4624 from the **identical source IP** for the **identical account** within minutes confirms
the guessed password was correct — this is **credential compromise, not just an attempt**.
Alternative explanation considered: internal password-spray by a misconfigured service —
ruled out (source is the dedicated adversary node; account is the designated test account).

## 5. Impact Assessment

- The attacker obtained **valid interactive/network access** as `testuser`.
- Per the lab RBAC matrix, `testuser` is a standard user (*verify group membership after
  execution* — if it is local admin, severity stands; if not, still Critical because rule
  `100102` policy treats post-brute-force success as compromise).
- Potential follow-on actions in scope: SMB share access, local recon (SIM-01 techniques),
  persistence installation (SIM-04).
- **Severity rationale (per rubric):** confirmed valid-account use after attack activity → 🔴 Critical.

## 6. Response Actions

| # | Action | Time | Result |
|---|--------|------|--------|
| 1 | Disabled `testuser` (`net user testuser /active:no`) | ⟨12:47:30⟩ | Account cannot authenticate |
| 2 | Host firewall rule blocking `192.168.1.8` inbound | ⟨12:48:10⟩ | Source isolated at endpoint |
| 3 | Searched estate for the same source IP / account | ⟨12:50:00⟩ | No further hits outside `WIN11-PRO` |
| 4 | Monitoring verified intact (agent `Active`) | ⟨12:52:00⟩ | No telemetry gap |

## 7. Root Cause / Threat Narrative

Simulated adversary access to the lab subnet (dedicated attacker VM) combined with a
**weak password on a valid account**. In production terms: exposed authentication surface
(SMB/RDP) + no lockout/cool-off policy + no MFA. The attack required **no exploit** —
purely credential guessing against a legitimate service.

## 8. Detection Gaps & Improvements

- **Worked well:** threshold rule `100101` caught the burst within ~2 minutes; correlation
  rule `100102` flagged the success — the exact "attempt → success" chain a SOC must never miss.
- **Gap:** no alert on the *first* anomalous logon source for this account (impossible-login
  geography / new-source velocity). **Proposed rule:** alert when an account first-ever
  authenticates from a new source IP within X days (baseline-building rule).
- **Process improvement:** auto-escalate any `100102` to P1 with pre-written containment
  runbook (account disable + session revocation).

## 9. Escalation Notes (Tier 2/3)

> Escalating to Tier 2 for host forensics on `WIN11-PRO`. Recommend immediate password
> reset and session revocation for `testuser`, and a 24-hour hunt for source `192.168.1.8`
> across the estate. Detection gap noted: brute force and post-success were caught, but the
> follow-on SMB session itself generates no dedicated alert — proposed rule attached
> (session anomaly after `100102`). No evidence of persistence at time of writing
> (SIM-04 checks negative — confirm during execution).

## 10. References

- MITRE ATT&CK: [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · [T1078](https://attack.mitre.org/techniques/T1078/)
- Rules: `100100` `100101` `100102` ([`../configs/local_rules.xml`](../configs/local_rules.xml))
- Runbook: [`../simulations/SIM-02-brute-force.md`](../simulations/SIM-02-brute-force.md)
- Queries: [`../queries/credential-access.md`](../queries/credential-access.md)
