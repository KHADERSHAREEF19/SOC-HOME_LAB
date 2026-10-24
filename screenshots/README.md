# 📸 Evidence & Screenshots

This folder holds the **visual proof** for the lab. Screenshots are captured **only from
this lab** during real simulation runs — never generated, never borrowed. Recruiters and
hiring managers ask candidates to walk through their screenshots in interviews;
authentic work always wins.

## Capture rules (professional quality)

1. **One idea per screenshot** — don't cram three findings into one image.
2. **Timestamps visible** — zoom/crop so the event time is readable (they anchor the report timeline).
3. **Readable fonts** — full-screen terminal / Splunk Web at a reasonable font size before capturing.
4. **Show the context bar** — window title, host name, or the Splunk Web URL (`http://192.168.1.25:8000`) where possible.
5. **Redact nothing in this lab** — the lab uses fake accounts (`testuser`, `svc_backdoor`) and lab IPs only.
   (Good habit: if you ever screenshot real environments, redact hostnames/usernames.)
6. **PNG format**, named per the checklist below — file names are referenced by the
   runbooks and incident reports.

## Naming checklist

| File name | Captured in | What it shows |
|-----------|-------------|---------------|
| `01_virtualbox_network.png` | Setup | VirtualBox Host-Only / Internal network settings (isolation proof) |
| `02_splunk_forward_server.png` | Setup | `splunk list forward-server` on the DC (→ `192.168.1.25:9997`) + Splunk Web `stats count by sourcetype, host` proving ingestion |
| `03_sysmon_event_viewer.png` | Setup | Sysmon events in Splunk (event XML view of EventCode 1) |
| `01a_nmap_scan.png` | SIM-01 | Kali terminal: nmap service scan results against the DC |
| `01b_ad_enumeration.png` | SIM-01 | AD enumeration commands (`ldapsearch` / `net group "Domain Admins" /domain`) |
| `01c_splunk_ad_enum_results.png` | SIM-01 | SPL results of `01-ad-enumeration.spl` |
| `04_hydra_bruteforce.png` | SIM-02 | Kali terminal: Hydra brute force in progress |
| `05_event_4625_spike.png` | SIM-02 | SPL results showing the 4625 spike during the attack |
| `06_splunk_alert_bruteforce.png` | SIM-02 | Saved search / Triggered Alert with the `Status` column |
| `07a_powershell_cradle.png` | SIM-03 | PowerShell download cradle + benign payload output |
| `07b_sysmon_event1_powershell.png` | SIM-03 | Raw Sysmon Event 1 in Splunk (suspicious command line) |
| `07_splunk_alert_powershell.png` | SIM-03 | SPL results of `03-powershell-execution.spl` |
| `08a_account_commands.png` | SIM-04 | `net user` / `net group` backdoor account commands |
| `08b_event_4720_4728.png` | SIM-04 | Raw Security events 4720/4728 in Splunk |
| `08_splunk_alert_account.png` | SIM-04 | SPL results with the `Action` column |
| `09a_wevtutil_clear.png` | SIM-05 | `wevtutil cl Security` execution |
| `09_event_1102_log_cleared.png` | SIM-05 | EventCode 1102 results / Triggered Alert |
| `09b_forwarder_stopped.png` | SIM-05 | Forwarder stopped + event-volume gap in Splunk |
| `10a_eicar_download.png` | SIM-06 | EICAR file delivery/download |
| `10_splunk_alert_eicar.png` | SIM-06 | SPL results of `06-eicar-file-create.spl` |
| `10b_sysmon_event11.png` | SIM-06 | Raw Sysmon Event 11 (file create) in Splunk |
| `11_splunk_dashboard.png` | Any | Custom SOC dashboard (failed vs successful logons, top source IPs, alert table) |
| `12_splunk_web_from_kali.png` | Setup | Splunk Web `http://192.168.1.25:8000` open in the **Kali browser** (isolation + access path) |

## After capturing

1. Drop the files in this folder with the exact names above.
2. Uncomment the image embeds at the bottom of the root [`../README.md`](../README.md)
   (Section 7) so the showcase renders inline.
3. Reference each screenshot from its runbook's **Evidence Checklist** and the incident report.

> Screenshot budget: the checklist above is 20+ items, but the **minimum recruiter-visible
> set** is `01`, `02`, `04`, `05`, `06`, `07`, `09_event_1102`, `10_splunk_alert_eicar`,
> `11_splunk_dashboard` — prioritize those if time is limited.
