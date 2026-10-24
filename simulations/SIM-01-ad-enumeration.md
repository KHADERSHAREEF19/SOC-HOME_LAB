# SIM-01 — AD Enumeration & Network Discovery

| | |
|---|---|
| **ID** | SIM-01 |
| **ATT&CK** | T1087.002 Account Discovery: Domain Account · T1069.002 Permission Groups Discovery: Domain Groups · T1046 Network Service Discovery |
| **Tactic** | Discovery |
| **Attacker** | Kali Linux `192.168.1.8` |
| **Target** | Windows Server 2022 Domain Controller `192.168.1.11` (Active Directory) |
| **Detection** | Saved search **"AD Enumeration - Object Access 4662 4661"** → [`queries/01-ad-enumeration.spl`](../queries/01-ad-enumeration.spl) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Emulate the reconnaissance an attacker performs against a **real Active Directory
environment**: network scanning first, then AD/permission-group enumeration. The
detection leverages **directory-service audit events (4662/4661)** — the enterprise
telemetry that only exists because the target is a Domain Controller.

## Scope & Safety

- Target is `192.168.1.11` only (the lab's own DC), on the isolated internal subnet.
- Nmap/enum tooling runs from Kali against the lab target only — never scan the host
  machine or any LAN/external address.

## Prerequisites

- [ ] DC promoted (`Install-ADDSForest`), test domain (e.g. `lab.local`) in place
- [ ] **Audit Directory Service Access** enabled (see [`../configs/sysmon-config-notes.md`](../configs/sysmon-config-notes.md))
- [ ] Universal Forwarder shipping `Security` + `Sysmon` to Splunk (`inputs.conf` applied)
- [ ] Time range in Splunk Web set to *Last 30 minutes*

---

## 1. Attack Execution

### Phase A — Network service discovery (Kali)

```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Service/version + OS fingerprint against the Domain Controller
nmap -sS -sV -O -A 192.168.1.11

# AD-focused: LDAP/SMB/Kerberos ports (389/636/445/88/3268 are the DC fingerprint)
nmap -p 88,135,139,389,445,636,3268 -sV 192.168.1.11
```

📸 Screenshot: `screenshots/01a_nmap_scan.png` — nmap output showing DC services.

### Phase B — Active Directory enumeration

From Kali against the DC (LDAP/SMB enumeration):

```bash
# LDAP enumeration of domain objects (generates 4662 object-access events)
ldapsearch -x -H ldap://192.168.1.11 -b "DC=lab,DC=local" "(objectClass=*)" dn

# SMB/NetBIOS enumeration
enum4linux-ng -A 192.168.1.11
```

From a domain-joined Windows host (or the DC console as a standard domain user):

```cmd
net group "Domain Admins" /domain
net group "Domain Users" /domain
net user /domain
nltest /dclist:lab.local
```

📸 Screenshot: `screenshots/01b_ad_enumeration.png` — enumeration commands + output.

## 2. Expected Telemetry

| Action | Source | EventCode | Where to look |
|--------|--------|-----------|---------------|
| AD object access (LDAP queries, object reads) | `WinEventLog:Security` | **4662 / 4661** | Splunk: `index=main` |
| Group/user enumeration bursts | same | 4662 spike by `Account_Name` | detection SPL result |
| Nmap from Kali | ⚠️ **no native Windows events** — see gap analysis below | — | — |

## 3. Detection (SPL)

Run in Splunk Web (raw file: [`01-ad-enumeration.spl`](../queries/01-ad-enumeration.spl)):

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4662 OR EventCode=4661
| stats count by Account_Name, Object_Type, Source_Network_Address
| sort - count
```

Expected: the enumerating account tops the list with a high `count` against AD object
types (e.g. `domainDNS`, `user`, `group`) from `Source_Network_Address=192.168.1.8`
(or the domain-joined test host).

📸 Screenshot: `screenshots/01c_splunk_ad_enum_results.png` — SPL search results.

## 4. Triage Walkthrough

1. Open the saved-search alert (Triggered Alerts) or run the SPL for the window.
2. Identify the top `Account_Name` by count — high-volume object access from one
   principal in minutes = enumeration, not normal application behavior.
3. Check `Object_Type` values: a mix of `group`/`user`/`domainDNS` reads is the classic
   "someone is mapping the domain" signature.
4. Pivot ([pivots](../queries/README.md)): correlate the same account with 4624 logons
   (which host/session ran the queries?).
5. Decide severity: reconnaissance alone = Medium; if followed by SIM-02-style auth
   attacks, escalate and merge into one incident timeline.

## 5. Visibility Gap Analysis *(this section is the differentiator)*

Inbound Nmap SYNs produce **no Windows events** — that is normal, not a lab failure.
Production SOC coverage for T1046 comes from:

| Control | Signal it would add | Stretch goal |
|---------|---------------------|--------------|
| Windows Firewall logging / WFP (5156/5152) | Per-port allowed/blocked connections | Enable WFP auditing, add `WinEventLog` input |
| IDS (Suricata/Snort) | `ET SCAN` nmap signatures | Add a Suricata VM, forward alerts to Splunk |
| NetFlow | Scan traffic pattern from `192.168.1.8` | pfSense in the path |

Writing "external scans are invisible in my current telemetry — here is what I'd add"
shows **telemetry maturity**, which is exactly what interviewers probe for.

## 6. Response & Cleanup

- [ ] No artifacts left behind (SIM-01 creates none — verify anyway)
- [ ] Note the enumeration window's start/end for later correlation (SIM-02)

## 7. Evidence Checklist

- [ ] `01_virtualbox_network.png` (from setup — network isolation)
- [ ] `01a_nmap_scan.png`
- [ ] `01b_ad_enumeration.png`
- [ ] `01c_splunk_ad_enum_results.png` — SPL results showing the enumeration burst
