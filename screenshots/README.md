# 📸 Evidence & Screenshots

This folder holds the **visual proof** for the lab. Screenshots are captured **only from
this lab** during real simulation runs — never generated, never borrowed. Recruiters and
hiring managers ask candidates to walk through their screenshots in interviews;
authentic work always wins.

## Capture rules (professional quality)

1. **One idea per screenshot** — don't cram three findings into one image.
2. **Timestamps visible** — zoom/crop so the event time is readable (they anchor the report timeline).
3. **Readable fonts** — full-screen terminal at a reasonable font size before capturing.
4. **Show the context bar** — window title, host name, or dashboard URL where possible.
5. **Redact nothing in this lab** — the lab uses fake accounts (`testuser`) and lab IPs only.
   (Good habit: if you ever screenshot real environments, redact hostnames/usernames.)
6. **PNG format**, named per the checklist below — file names are referenced by the
   runbooks and incident reports.

## Naming checklist

| File name | Captured in | What it shows |
|-----------|-------------|---------------|
| `01_virtualbox_network.png` | Setup Phase 1 | VirtualBox host-only network settings (isolation proof) |
| `02_wazuh_agent_active.png` | Setup Phase 3 | Wazuh → Agents → `WIN11-PRO` **Active** |
| `03_sysmon_event_viewer.png` | Setup Phase 3 | Event Viewer showing Sysmon/Operational events flowing |
| `01a_nmap_scan.png` | SIM-01 | Kali terminal: nmap service scan results |
| `01b_recon_commands.png` | SIM-01 | cmd/PowerShell recon cluster on the endpoint |
| `01c_wazuh_discovery_alert.png` | SIM-01 | Wazuh alert: rule `100140` |
| `04_hydra_bruteforce.png` | SIM-02 | Kali terminal: Hydra brute force in progress |
| `05_event_4625_spike.png` | SIM-02 | Event Viewer / dashboard: 4625 spike during the attack |
| `06_wazuh_alert_bruteforce.png` | SIM-02 | Wazuh alert: rules `100101` / `100102` |
| `07a_powershell_cradle.png` | SIM-03 | PowerShell download cradle + benign payload output |
| `07b_sysmon_eid1_powershell.png` | SIM-03 | Sysmon EID 1 with suspicious command line |
| `07_powershell_alert.png` | SIM-03 | Wazuh alert: rule `100110` |
| `08a_persistence_commands.png` | SIM-04 | `schtasks /create` + `reg add` commands |
| `08b_event_4698.png` | SIM-04 | Security 4698 (or Sysmon 13) in Event Viewer |
| `08_persistence_alert.png` | SIM-04 | Wazuh alert: rules `100130` / `100135` |
| `09a_wevtutil_clear.png` | SIM-05 | `wevtutil cl Security` execution |
| `09_event_1102_log_cleared.png` | SIM-05 | Event 1102 visible after the clear |
| `09b_agent_disconnected.png` | SIM-05 | Wazuh agent disconnect / telemetry gap |
| `10a_eicar_download.png` | SIM-06 | EICAR file delivery/download |
| `10_defender_eicar_alert.png` | SIM-06 | Defender 1116/1117 or Wazuh malware alert |
| `10b_sysmon_eid11.png` | SIM-06 | Sysmon file-create event |
| `11_wazuh_dashboard_correlation.png` | Any | Dashboard: correlated view (top source IPs / timeline) |

## After capturing

1. Drop the files in this folder with the exact names above.
2. Uncomment the image embeds at the bottom of the root [`../README.md`](../README.md)
   (Section 7) so the showcase renders inline.
3. Reference each screenshot from its runbook's **Evidence Checklist** and the incident report.

> Screenshot budget: the checklist above is 20+ items, but the **minimum recruiter-visible
> set** is `01`, `02`, `04`, `05`, `06`, `07`, `09_event_1102`, `10_defender_eicar`,
> `11_wazuh_dashboard_correlation` — prioritize those if time is limited.
