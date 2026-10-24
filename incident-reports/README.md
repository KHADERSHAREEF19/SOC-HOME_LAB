# 🧾 Incident Response & Reporting

A SOC analyst's real deliverable is not screenshots — it is **the ticket**. This folder
demonstrates that skill: how an alert becomes a documented, escalated incident.

## The triage loop used in this lab

```
        ┌────────────────────────────────────────────────────────┐
        │  1. VALIDATE   Is this a true positive? (vs noise/FP)   │
        │  2. SCOPE      Which hosts, accounts, IPs, time window? │
        │  3. CONTAIN    Disable account / isolate host / block IP│
        │  4. ERADICATE  Remove persistence, malware, artifacts   │
        │  5. RECOVER    Restore monitoring, verify baseline      │
        │  6. REPORT     Ticket + escalation with evidence        │
        └────────────────────────────────────────────────────────┘
                          ▲ detection rules + queries feed this
```

## Files in this folder

| File | Purpose |
|------|---------|
| [`template.md`](template.md) | Reusable incident report template — one per simulation |
| [`IR-2026-001-brute-force.md`](IR-2026-001-brute-force.md) | **Worked example** from SIM-02 (format showcase) |

> ⚠️ **Authenticity:** `IR-2026-001` is a **format example** — it is explicitly marked as
> placeholder content. When you execute SIM-02, overwrite it with your **real** timestamps,
> alert IDs and screenshots. Never present fabricated evidence as performed work;
> in interviews you will be asked to walk through the timeline, and authenticity shows.

## Ticket-quality checklist (what reviewers score)

- [ ] **One-page summary** a manager can read in 60 seconds (severity + impact + status)
- [ ] **Timeline with real timestamps** (timezone noted) — from first event to containment
- [ ] **Evidence** — query used, result, screenshot reference, event/alert IDs
- [ ] **Attribution basics** — source IP, account, host names
- [ ] **Severity justified** — not "high because it felt high": tied to impact + confidence
- [ ] **Actions taken** — containment steps with timestamps
- [ ] **Detection improvement** — what rule/query would catch this faster next time
- [ ] **Escalation note** — what Tier-2/3 should investigate next

## Severity rubric used

| Severity | Criteria (this lab) | Example |
|----------|---------------------|---------|
| 🔴 Critical | Confirmed compromise: valid creds used, persistence, or defenses impaired | SIM-02 success (rule `100102`), SIM-05 |
| 🟠 High | Successful attack technique detected, scope contained | Brute-force burst, EICAR delivery |
| 🟡 Medium | Suspicious activity, no confirmed success | Encoded PowerShell without follow-on |
| 🔵 Low | Recon/noise needing monitoring only | Standalone `whoami` |

## Escalation language (copy this tone)

> *Escalating to Tier 2 for host forensics on WIN11-PRO. Recommend immediate password
> reset and session revocation for `testuser`, and a 24-hour hunt for the same source IP
> across the estate. Detection gap noted: brute force was caught, but the follow-on SMB
> session was not alerting — proposed rule attached.*

That paragraph style — facts, impact, actions, gap, proposal — is what senior analysts
and hiring managers want to see from a Tier-1 candidate.
