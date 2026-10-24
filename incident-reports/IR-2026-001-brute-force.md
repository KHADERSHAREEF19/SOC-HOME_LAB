# Incident Report — IR-2026-001: Brute-Force Attack Followed by Valid Account Use

> ⚠️ **PLACEHOLDER EXAMPLE — format showcase.** The structure, analysis style and
> escalation language below show the *target quality* for a completed report.
> All timestamps, counts and alert names are **illustrative placeholders** (marked `⟨…⟩`).
> When SIM-02 is executed, replace them with real captured data before presenting
> this repository as executed work.

| Field | Value |
|-------|-------|
| **Report ID** | IR-2026-001 |
| **Title** | Brute-force password attack against `WIN-DC01` with confirmed successful logon |
| **Severity** | 🔴 **Critical** — valid credential compromised (`Status: CRITICAL…`) |
| **Status** | Contained → Closed (lab) |
| **Category** | Credential Access — T1110.001 / T1078 |
| **Related simulation** | [SIM-02](../simulations/SIM-02-brute-force.md) |
| **SIEM** | Splunk Enterprise `http://192.168.1.25:8000` — index `main` |
| **Analyst** | Khader Shareef Madani (Tier 1 — triage & documentation) |
| **Date opened** | ⟨2026-10-24 12:38 UTC+05:30⟩ |
| **Date closed** | ⟨2026-10-24 13:05 UTC+05:30⟩ |

## 1. Summary

The Splunk saved search **"Brute Force - 4625 4624 Correlation"** triggered after ⟨N⟩
failed logons (EventCode 4625) against the domain account `testuser` on `WIN-DC01`
(Domain Controller), all originating from `Source_Network_Address=192.168.1.8` (lab
adversary node "Kali"). Within ⟨minutes⟩ of the burst a **successful logon (4624)** from
the same source pushed the correlation result to
**`Status: "CRITICAL: Potential Compromise After Brute Force"`** — the attacker
**validly authenticated** with the guessed password. The account was disabled and the
source IP blocked at the DC firewall at ⟨time⟩. Full simulation documentation:
[SIM-02](../simulations/SIM-02-brute-force.md).

## 2. Affected Assets & Accounts

| Type | Value | Role |
|------|-------|------|
| Host | `WIN-DC01` (`192.168.1.11`) | Windows Server 2022 — Domain Controller (lab `lab.local`) |
| Account | `testuser` (`Account_Name`) | Targeted domain account (disposable lab account) |
| Source IP | `192.168.1.8` (`Source_Network_Address`) | Lab adversary node (Kali Linux) |

## 3. Timeline (UTC+05:30)

| Time | Event | Source |
|------|-------|--------|
| ⟨12:31:02⟩ | First failed logon — EventCode **4625**, `testuser`, from `192.168.1.8` | `WinEventLog:Security` (index `main`) |
| ⟨12:31:02–12:33:41⟩ | ⟨N⟩ failed logons (4625) from `192.168.1.8` | indexed via Universal Forwarder |
| ⟨12:33:42⟩ | **Saved search triggered** — `Failed_Logons > 5` | Splunk → Triggered Alerts |
| ⟨12:34:17⟩ | Successful logon — EventCode **4624**, `testuser`, from `192.168.1.8` | `WinEventLog:Security` |
| ⟨12:34:42⟩ | Correlation re-run shows `Status: CRITICAL: Potential Compromise After Brute Force` | Splunk search |
| ⟨12:38:00⟩ | Triage started; SPL pivots executed ([§4](#4-observations--evidence)) | Analyst |
| ⟨12:47:30⟩ | Containment: `testuser` disabled; firewall rule blocking `192.168.1.8` | Analyst |
| ⟨13:05:00⟩ | Report completed; escalated to Tier 2 for review | Analyst |

## 4. Observations & Evidence

### 4.1 Detection

- **Saved search:** `Brute Force - 4625 4624 Correlation` ([`../configs/savedsearches.conf`](../configs/savedsearches.conf))
- **SPL used:**

  ```spl
  index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
  | stats count(eval(EventCode=4625)) as Failed_Logons, count(eval(EventCode=4624)) as Successful_Logons by Account_Name, Source_Network_Address
  | where Failed_Logons > 5
  | eval Status=if(Successful_Logons>0, "CRITICAL: Potential Compromise After Brute Force", "WARNING: Brute Force Attempt")
  ```

- **Result row:**

  | Account_Name | Source_Network_Address | Failed_Logons | Successful_Logons | Status |
  |--------------|------------------------|---------------|-------------------|--------|
  | `testuser` | `192.168.1.8` | ⟨N⟩ | ⟨1⟩ | CRITICAL: Potential Compromise After Brute Force |

### 4.2 Evidence screenshots

| # | File | Shows |
|---|------|-------|
| 1 | `screenshots/04_hydra_bruteforce.png` | Attack execution (Hydra against `192.168.1.11`) |
| 2 | `screenshots/05_event_4625_spike.png` | 4625 spike in SPL search results |
| 3 | `screenshots/06_splunk_alert_bruteforce.png` | Saved search / Triggered Alert with `Status` column |

### 4.3 Analysis

The volume, pacing and single-source/single-account pattern match an **automated password
guessing tool** (consistent with the lab's Hydra execution), not a user mistyping a password
(typo patterns: 1–3 attempts, multiple accounts, business-hours timing). The subsequent
EventCode 4624 from the **identical `Source_Network_Address`** for the **identical
`Account_Name`** within minutes confirms the guessed password was correct — this is
**credential compromise, not just an attempt**. Alternative explanation considered:
service account lockout storm from a misconfigured application — ruled out (source is the
dedicated adversary node; account is the designated test account).

## 5. Impact Assessment

- The attacker obtained **valid domain authentication** as `testuser` on the Domain
  Controller — the most security-sensitive host in the estate.
- Per the lab RBAC matrix, `testuser` is a standard domain user (*verify group membership
  after execution* — check `MemberName` events via the SIM-04 SPL).
- Potential follow-on actions in scope: share access, AD enumeration (SIM-01),
  rogue account persistence (SIM-04).
- **Severity rationale (per rubric):** confirmed valid-account use after attack activity → 🔴 Critical.

## 6. Response Actions

| # | Action | Time | Result |
|---|--------|------|--------|
| 1 | Disabled `testuser` (`net user testuser /active:no /domain`) | ⟨12:47:30⟩ | Account cannot authenticate |
| 2 | DC firewall rule blocking `192.168.1.8` inbound | ⟨12:48:10⟩ | Source isolated at endpoint |
| 3 | Estate-wide SPL hunt for the same source IP/account | ⟨12:50:00⟩ | No further hits outside `WIN-DC01` |
| 4 | Monitoring verified intact (`splunk list forward-server`, event flow) | ⟨12:52:00⟩ | No telemetry gap |

## 7. Root Cause / Threat Narrative

Simulated adversary access to the lab subnet (dedicated attacker VM) combined with a
**weak password on a valid domain account**. In production terms: exposed authentication
surface (SMB) + no lockout/cool-off policy + no MFA. The attack required **no exploit** —
purely credential guessing against a legitimate service on the Domain Controller.

## 8. Detection Gaps & Improvements

- **Worked well:** the SPL correlation (`Failed_Logons > 5` + success follow-on) caught the
  full attempt → compromise chain — the exact story a SOC must never miss.
- **Gap:** no alert on the *first* anomalous logon source for this account (new-source
  velocity). **Proposed SPL:**

  ```spl
  index=main sourcetype="WinEventLog:Security" EventCode=4624
  | stats earliest(_time) as first_seen values(Source_Network_Address) as sources by Account_Name
  | where mvcount(sources) > 1
  ```

- **Process improvement:** auto-escalate any `Status="CRITICAL…"` result to P1 with a
  pre-written containment runbook (account disable + session revocation).

## 9. Escalation Notes (Tier 2/3)

> Escalating to Tier 2 for host forensics on `WIN-DC01`. Recommend immediate password
> reset and session revocation for `testuser`, and a 24-hour estate-wide hunt for source
> `192.168.1.8` using the pivots in [`../queries/README.md`](../queries/README.md).
> Detection gap noted: brute force and post-success were caught, but the follow-on SMB
> session itself generates no dedicated alert — proposed SPL attached (session anomaly
> after `Status=CRITICAL`). No evidence of persistence at time of writing (SIM-04 checks
> negative — confirm during execution).

## 10. References

- MITRE ATT&CK: [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · [T1078](https://attack.mitre.org/techniques/T1078/)
- Saved search: `Brute Force - 4625 4624 Correlation` ([`../configs/savedsearches.conf`](../configs/savedsearches.conf))
- Query file: [`../queries/02-brute-force.spl`](../queries/02-brute-force.spl)
- Runbook: [`../simulations/SIM-02-brute-force.md`](../simulations/SIM-02-brute-force.md)
