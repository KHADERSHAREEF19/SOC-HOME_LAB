# SIM-02 — Brute Force → Valid Account ⭐ (flagship simulation)

| | |
|---|---|
| **ID** | SIM-02 |
| **ATT&CK** | T1110.001 Brute Force: Password Guessing · T1078 Valid Accounts |
| **Tactic** | Credential Access |
| **Attacker** | Kali Linux `192.168.1.8` (Hydra) |
| **Target** | Windows Server 2022 DC `192.168.1.11` — SMB/network logon surface |
| **Detection** | Saved search **"Brute Force - 4625 4624 Correlation"** → [`queries/02-brute-force.spl`](../queries/02-brute-force.spl) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Run a controlled password attack against a dedicated lab **domain account**, watch the
classic **4625 → 4624** story unfold in Splunk, and produce a **full incident report**
([`../incident-reports/IR-2026-001-brute-force.md`](../incident-reports/IR-2026-001-brute-force.md)).
This single simulation demonstrates the complete SOC loop: attack → telemetry → SPL
detection → triage → containment → report.

## Scope & Safety

- **Target account:** a disposable domain account (e.g. `testuser`) with a weak password,
  created on the DC for the exercise — never use a real/personal account.
- Attack `192.168.1.11` only, from `192.168.1.8` only.
- Keep the attempt rate modest (Hydra `-t 4`) so the lab stays usable and the timeline is readable.

## Prerequisites

- [ ] `testuser` exists in `lab.local` with a known weak password (`Summer2026!` or similar)
- [ ] SMB (445) reachable from Kali: `smbclient -L //192.168.1.11 -U testuser`
- [ ] Universal Forwarder healthy: `splunk list forward-server` shows `192.168.1.25:9997`
- [ ] Splunk time range set to cover the attack window

---

## 1. Attack Execution

### Phase A — Password spraying / brute force (Hydra)

```bash
# wordlist: put the real password near the END so the burst is visible first
hydra -l testuser -P ./wordlist.txt -t 4 -f smb://192.168.1.11
```

Watch the 4625s roll in while it runs (this is your "attack in progress" moment):

📸 Screenshot: `screenshots/04_hydra_bruteforce.png` — Hydra terminal mid-run
(showing attempts against `192.168.1.11`).

Variants worth a line in your notes (same tactic, different surface):

```bash
hydra -l testuser -P ./wordlist.txt -t 4 rdp://192.168.1.11   # logon type 10
hydra -l testuser -P ./wordlist.txt -t 4 smb://192.168.1.11   # network logon (type 3)
```

### Phase B — Valid account use (post-compromise)

When Hydra reports success, prove the credential works like an attacker would:

```bash
smbclient //192.168.1.11/C$ -U testuser
# or interactive WinRM/RDP session with the found password
```

## 2. Expected Telemetry

| Phase | Source | EventCode | Signature in Splunk |
|-------|--------|-----------|---------------------|
| Spray | `WinEventLog:Security` | **4625** | `Account_Name=testuser`, `Source_Network_Address=192.168.1.8` |
| Success | `WinEventLog:Security` | **4624** | same account + source, logon type 3/10 |
| Detection | Saved search **Brute Force - 4625 4624 Correlation** | — | `Failed_Logons > 5`; `Status` = `WARNING: Brute Force Attempt`, escalating to `CRITICAL: Potential Compromise After Brute Force` when a 4624 follows |

📸 Screenshots:
- `screenshots/05_event_4625_spike.png` — SPL results showing the 4625 spike (`stats count by EventCode`)
- `screenshots/06_splunk_alert_bruteforce.png` — the saved search / Triggered Alert with the `Status` field

## 3. Detection (SPL)

Run in Splunk Web (raw file: [`02-brute-force.spl`](../queries/02-brute-force.spl)):

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as Failed_Logons, count(eval(EventCode=4624)) as Successful_Logons by Account_Name, Source_Network_Address
| where Failed_Logons > 5
| eval Status=if(Successful_Logons>0, "CRITICAL: Potential Compromise After Brute Force", "WARNING: Brute Force Attempt")
```

The `Status` column is the triage decision, encoded in SPL: **attempts only** vs
**compromise confirmed**. That line is a great interview talking point.

## 4. Triage Walkthrough (mirror this in the incident report)

1. **Validate:** `Failed_Logons > 5` from one `Source_Network_Address` against one
   `Account_Name` = true positive (rule of thumb: 1–3 failures = typo, 5+ rapid = tool).
2. **Scope:** counts, first/last seen, targeted account(s), source IP ([pivots](../queries/README.md)).
3. **Determine outcome:** `Successful_Logons > 0`? → `CRITICAL` — compromise confirmed.
   Record `TargetLogonType` (3 = SMB/network, 10 = RDP).
4. **Impact:** what can `testuser` access in the domain? (group membership — pivot to SIM-04 SPL)
5. **Contain:** disable `testuser` (`net user testuser /active:no /domain`), block
   `192.168.1.8`, consider isolating the DC if the account was privileged.
6. **Escalate & report:** fill [`../incident-reports/template.md`](../incident-reports/template.md)
   → this becomes **IR-2026-001**.

## 5. Response & Cleanup

```cmd
:: On the DC — contain
net user testuser /active:no /domain
:: Optionally block the attacker at the DC firewall
netsh advfirewall firewall add rule name="BLOCK-Kali-lab" dir=in action=block remoteip=192.168.1.8
```

- [ ] Re-enable `testuser` (or delete it) after documentation; lab returns to baseline
- [ ] Note containment timestamps in the report

## 6. Evidence Checklist

- [ ] `04_hydra_bruteforce.png`
- [ ] `05_event_4625_spike.png`
- [ ] `06_splunk_alert_bruteforce.png`
- [ ] Incident report `IR-2026-001` completed with real timestamps / search names

## 7. Lessons / Tuning Notes *(fill after execution)*

- Was `Failed_Logons > 5` the right threshold for your Hydra pacing (`-t 4`)? Record what
  you observed — and how you'd tune `stats`/`where` for a slow, low-and-slow spray instead.
- Any false-positive considerations for shared/service accounts? (worth a sentence — shows ops thinking)
