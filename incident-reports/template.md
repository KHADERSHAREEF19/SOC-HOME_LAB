# Incident Report — IR-YYYY-NNN: <title>

| Field | Value |
|-------|-------|
| **Report ID** | IR-YYYY-NNN |
| **Title** | e.g. Brute-force attack against WIN-DC01 |
| **Severity** | 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low |
| **Status** | Open / Contained / Closed |
| **Category** | e.g. Credential Access — T1110.001 |
| **Related simulation** | SIM-XX |
| **SIEM** | Splunk Enterprise — `http://192.168.1.25:8000` (index `main`) |
| **Analyst** | Khader Shareef Madani |
| **Date opened** | YYYY-MM-DD HH:MM (UTC+05:30 / note your TZ) |
| **Date closed** | YYYY-MM-DD HH:MM |

## 1. Summary

*2–4 sentences. A manager should understand the incident without reading further:
what happened, to which asset, was it successful, what is the current status.*

## 2. Affected Assets & Accounts

| Type | Value | Role |
|------|-------|------|
| Host | | e.g. WIN-DC01 (Domain Controller) |
| Account | | `Account_Name` field |
| Source IP | | `Source_Network_Address` field |

## 3. Timeline (all times in <TZ>)

| Time | Event | Source |
|------|-------|--------|
| | First observed activity (EventCode …) | `WinEventLog:Security` |
| | Saved search triggered | Splunk → Triggered Alerts |
| | Triage started | Analyst |
| | Containment action | Analyst |
| | Monitoring restored / closed | Analyst |

## 4. Observations & Evidence

### 4.1 Detection

- **Saved search / alert name:** (from [`../configs/savedsearches.conf`](../configs/savedsearches.conf))
- **SPL used:**
  ```spl
  ```
- **Key fields observed:** `EventCode`, `Account_Name`, `Source_Network_Address`,
  counts, time window

### 4.2 Evidence screenshots

| # | File | Shows |
|---|------|-------|
| | `screenshots/...` | |

### 4.3 Analysis

*What the evidence means: attempted vs successful, kill-chain position,
confidence level, alternative explanations considered (and ruled out).*

## 5. Impact Assessment

*What could the attacker access/do? Data/domain sensitivity of the host/account.
Why this severity level (tie it to the rubric in README.md).*

## 6. Response Actions

| # | Action | Time | Result |
|---|--------|------|--------|
| 1 | | | |

## 7. Root Cause / Threat Narrative

*How did this happen? (lab: simulated via SIM-XX; in production: phishing, exposed
service, weak password policy, etc.)*

## 8. Detection Gaps & Improvements

- **Gap:**
- **Proposed SPL change:** (paste the improved search)
- **Process improvement:**

## 9. Escalation Notes (Tier 2/3)

*What should the next tier investigate? Recommended hunts (with SPL), forensics, or
enterprise-wide sweeps.*

## 10. References

- MITRE ATT&CK: `Txxxx`
- Saved searches: `"…"` ([`../configs/savedsearches.conf`](../configs/savedsearches.conf))
- Related runbook: `simulations/SIM-XX-...md`
- Query files: `queries/XX-....spl`
