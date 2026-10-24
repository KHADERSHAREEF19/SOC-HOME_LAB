# SIM-01 — Network & Host Discovery

| | |
|---|---|
| **ID** | SIM-01 |
| **ATT&CK** | T1046 Network Service Discovery · T1082 System Information Discovery · T1087 Account Discovery · T1033 System Owner/User Discovery |
| **Tactic** | Reconnaissance / Discovery |
| **Attacker** | Kali Linux `192.168.1.8` |
| **Target** | Windows 11 `192.168.1.11` (console session) |
| **Detection rules** | `100140` (recon command cluster) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Emulate an actor performing **reconnaissance before the main attack**: external service
scanning from Kali, then internal host/account discovery commands on the endpoint.
Demonstrate (a) what telemetry a discovery burst produces, and (b) — just as important —
**what it does NOT produce** (the visibility gap analysis below).

## Scope & Safety

- Target is `192.168.1.11` only, on the host-only lab subnet.
- Nmap runs from Kali against the lab target only — never scan the host machine or LAN.

## Prerequisites

- [ ] All three VMs up; Wazuh agent `WIN11-PRO` **Active** in the dashboard
- [ ] Custom rules installed (rule `100140` active)
- [ ] Time range in the dashboard set to *Last 30 minutes*

---

## 1. Attack Execution

### Phase A — External scan from Kali (`192.168.1.8`)

```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Service/version + OS fingerprint against the target
nmap -sS -sV -O -A 192.168.1.11

# Aggressive full-port scan (noisy on purpose — this is what a SOC should worry about)
nmap -p- -T4 192.168.1.11
```

📸 Screenshot: `screenshots/01a_nmap_scan.png` — nmap output showing discovered
services (e.g. 135/139/445/3389).

### Phase B — Host/account discovery on the endpoint (simulated foothold)

Sign in to `192.168.1.11` as `testuser`, open `cmd.exe`, and run the classic recon cluster:

```cmd
whoami /all
systeminfo
ipconfig /all
net user
net localgroup administrators
tasklist
netstat -an
```

📸 Screenshot: `screenshots/01b_recon_commands.png` — cmd window with the command cluster.

## 2. Expected Telemetry

| Action | Source | Event | Where to look |
|--------|--------|-------|---------------|
| Recon command cluster | Sysmon EID 1 | `whoami`, `systeminfo`, … process creations within 5 min | Wazuh: Security Events |
| Cluster correlation | Wazuh rule `100140` | "Host/account discovery command cluster" alert | Wazuh: Alerts |
| Nmap from Kali | ⚠️ **none in default Windows logs** | see gap analysis below | — |

## 3. Detection

Query (see [`../queries/discovery.md`](../queries/discovery.md)):

```
rule.id : 100140
```

```
data.win.eventdata.commandLine : (whoami or systeminfo or netstat or net user)
```

## 4. Triage Walkthrough

1. Open the `100140` alert → confirm ≥3 distinct recon commands, same host, <5 min apart.
2. Note `user`, `parentImage` and the exact command lines into a timeline table.
3. Ask: does this user/role normally run these commands? (lab answer: no → true positive)
4. Pivot: what did this host do before/after the cluster? (`agent.name : WIN11-PRO` + time)
5. Decide: standalone recon event, or prelude to SIM-02? Correlate if in the same window.

## 5. Visibility Gap Analysis *(this section is the differentiator)*

Inbound Nmap SYNs produce **no Windows events** — that is normal, not a lab failure.
Production SOC coverage for T1046 comes from:

| Control | Signal it would add | Stretch goal |
|---------|---------------------|--------------|
| Windows Firewall logging / WFP (5156/5152) | Per-port allowed/blocked connections | Enable WFP auditing, ingest via agent |
| IDS (Suricata/Snort) | `ET SCAN` nmap signatures | Add a Suricata VM + `wazuh-agent` |
| NetFlow | Scan traffic pattern from `192.168.1.8` | pfSense in the path |

Writing "external scans are invisible in my current telemetry — here is what I'd add"
shows **telemetry maturity**, which is exactly what interviewers probe for.

## 6. Response & Cleanup

- [ ] No persistence left behind (SIM-01 creates none — verify anyway)
- [ ] Close cmd; note end time of the recon window for later correlation

## 7. Evidence Checklist

- [ ] `01_virtualbox_network.png` (from setup — network isolation)
- [ ] `01a_nmap_scan.png`
- [ ] `01b_recon_commands.png`
- [ ] `01c_wazuh_discovery_alert.png` — rule `100140` firing
