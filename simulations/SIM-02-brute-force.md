# SIM-02 — Brute Force → Valid Account ⭐ (flagship simulation)

| | |
|---|---|
| **ID** | SIM-02 |
| **ATT&CK** | T1110.001 Brute Force: Password Guessing · T1078 Valid Accounts |
| **Tactic** | Credential Access |
| **Attacker** | Kali Linux `192.168.1.8` (Hydra) |
| **Target** | Windows 11 `192.168.1.11` — SMB/WinRM/RDP logon surface |
| **Detection rules** | `100100` (base 4625) · `100101` (brute force) · `100102` (success after brute force) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Run a controlled password attack against a dedicated lab account, watch the classic
**4625 → 4624** story unfold in the SIEM, and produce a **full incident report**
([`../incident-reports/IR-2026-001-brute-force.md`](../incident-reports/IR-2026-001-brute-force.md)).
This single simulation demonstrates the complete SOC loop: attack → telemetry → detection →
triage → containment → report.

## Scope & Safety

- **Target account:** create a disposable `testuser` with a weak password (`Summer2026!`
  or similar) on the endpoint — never use a real/personal account.
- Attack `192.168.1.11` only, from `192.168.1.8` only.
- Keep the attempt rate modest (Hydra `-t 4`) so the lab stays usable and the timeline is readable.

## Prerequisites

- [ ] `testuser` exists on `192.168.1.11` with a known weak password
- [ ] SMB (445) reachable from Kali: `smbclient -L //192.168.1.11 -U testuser`
- [ ] Wazuh agent **Active**; rules `100100/100101/100102` installed
- [ ] Password wordlist prepared (e.g. small custom list of 20 candidates)

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
hydra -l testuser -P ./wordlist.txt -t 4 winrm://192.168.1.11  # WinRM
```

### Phase B — Valid account use (post-compromise)

When Hydra reports success, prove the credential works like an attacker would:

```bash
smbclient //192.168.1.11/C$ -U testuser          # or
evil-winrm -i 192.168.1.11 -u testuser -p '<found-password>'
```

## 2. Expected Telemetry

| Phase | Source | Event | Signature |
|-------|--------|-------|-----------|
| Spray | Security | **4625** failed logon | `targetUserName=testuser`, `ipAddress=192.168.1.8`, logonType 3/10 |
| Burst | Wazuh rule **`100101`** | Brute-force alert (level 12) | ≥8 fails / 120 s / same source IP |
| Success | Security | **4624** successful logon | same source IP, same account |
| Compromise | Wazuh rule **`100102`** | CRITICAL (level 14) | success within 10 min of the burst |

📸 Screenshots:
- `screenshots/05_event_4625_spike.png` — raw Security log or dashboard view of the 4625 spike
- `screenshots/06_wazuh_alert_bruteforce.png` — rule `100101` / `100102` on the dashboard

## 3. Detection

Queries (see [`../queries/credential-access.md`](../queries/credential-access.md)):

```
rule.id : (100101 or 100102)
```

```
data.win.system.eventID : (4625 or 4624) AND data.win.eventdata.ipAddress : 192.168.1.8
```

## 4. Triage Walkthrough (mirror this in the incident report)

1. **Validate:** 4625s from one external-ish source against one account = true positive.
2. **Scope:** count failures, first/last seen, targeted account(s), source IP, logon types.
3. **Determine outcome:** any 4624 from the same IP? → compromise confirmed; else "attempted".
4. **Impact:** what can `testuser` access? (local admin? shares?) — record group membership.
5. **Contain:** disable `testuser`, block `192.168.1.8` at the host firewall, isolate host if needed.
6. **Escalate & report:** fill [`../incident-reports/template.md`](../incident-reports/template.md)
   → this becomes **IR-2026-001**.

## 5. Response & Cleanup

```powershell
# On 192.168.1.11 — contain
net user testuser /active:no
# Optionally block the attacker at the endpoint firewall
netsh advfirewall firewall add rule name="BLOCK-Kali-lab" dir=in action=block remoteip=192.168.1.8
```

- [ ] Re-enable `testuser` (or delete it) after documentation, lab returns to baseline
- [ ] Note containment timestamps in the report

## 6. Evidence Checklist

- [ ] `04_hydra_bruteforce.png`
- [ ] `05_event_4625_spike.png`
- [ ] `06_wazuh_alert_bruteforce.png`
- [ ] Incident report `IR-2026-001` completed with real timestamps/alert IDs

## 7. Lessons / Tuning Notes *(fill after execution)*

- Was `8 fails / 120 s` the right threshold for your Hydra pacing? Record what you observed.
- Any false-positive considerations for shared accounts? (worth a sentence — shows ops thinking)
