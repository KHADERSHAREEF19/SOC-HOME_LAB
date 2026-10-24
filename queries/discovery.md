# Discovery — Host & Account Reconnaissance (SIM-01)

**ATT&CK:** T1046 (Network Service Discovery) · T1082 (System Information) · T1087 (Account Discovery) · T1033 (System Owner/User Discovery)
**Events:** Sysmon EID 1 (recon command process creation) · (optional) Sysmon EID 3, firewall logs
**Custom rules:** `100140`

---

## 1. Detection query — recon cluster fired?

```
rule.id : 100140
```

The rule counts **multiple distinct recon commands within 5 minutes** — a single
`whoami` is normal user behavior; `whoami` + `systeminfo` + `net user` in one burst is
an actor mapping the box.

## 2. Raw telemetry — the recon command cluster

```
data.win.eventdata.commandLine : (whoami or systeminfo or netstat or nltest or net user)
```

```
agent.name : WIN11-PRO AND data.win.system.eventID : 1
```

Build the timeline:

| Time | Command | Parent process | User | Legitimate? |
|------|---------|----------------|------|-------------|
| … | `whoami /all` | `cmd.exe` | … | ✗ cluster |
| … | `systeminfo` | `cmd.exe` | … | ✗ cluster |
| … | `net user` | `cmd.exe` | … | ✗ cluster |

## 3. External scan visibility — the honest answer (visibility gap analysis)

Inbound Nmap scans from Kali generate **no native Windows events** — Windows does not
log refused inbound SYNs by default. What a production SOC uses instead:

| Control | What it would show |
|---------|--------------------|
| Firewall logging (WFP events 5156/5152) | Allowed/blocked connection attempts per port |
| IDS/IPS (Snort/Suricata) | `ET SCAN` signatures for nmap-style probes |
| NetFlow / switch telemetry | Port-scan traffic pattern from 192.168.1.8 |
| Vulnerability scanner alerts | The same recon pattern seen from the defender side |

> Calling out what your lab **cannot** see is a senior habit: mature analysts document
> telemetry gaps instead of pretending the SIEM sees everything. Add WFP logging or a
> Suricata VM as a stretch goal if you want coverage here.

## 4. Scoping — was this the start of the kill chain?

```
agent.name : WIN11-PRO AND timestamp >= "attack window start"
```

Discovery usually precedes credential access. Check whether SIM-02 (brute force) follows
within the same session/host — if so, correlate them into **one** incident timeline
(bigger picture = better report).
