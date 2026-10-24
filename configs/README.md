# ⚙️ Configs — Splunk Forwarding & Detection Content

Everything in this folder is part of the **real telemetry pipeline and detection
layer** of the lab — the equivalent of production deployment configs, not sample files.

| File | Role | Where it runs |
|------|------|---------------|
| [`inputs.conf`](inputs.conf) | Universal Forwarder event collection: `Security`, `System`, `Sysmon/Operational` (XML) | Windows Server DC — `C:\Program Files\SplunkUniversalForwarder\etc\system\local\` |
| [`outputs.conf`](outputs.conf) | Forwarder → indexer shipping on **TCP 9997** | Windows Server DC — same `local\` folder |
| [`savedsearches.conf`](savedsearches.conf) | The 6 detection searches as scheduled Splunk alerts (SPL) | Splunk Enterprise — `/opt/splunk/etc/apps/search/local/` |
| [`sysmon-config-notes.md`](sysmon-config-notes.md) | Sysmon deployment on the DC + audit policy for AD events | Windows Server DC |

## Deployment order

### 1. Splunk Enterprise (Ubuntu Server `192.168.1.25`)

```bash
# Install (tarball or .deb from splunk.com — free Splunk Enterprise trial/lab license)
cd /opt/splunk/bin
./splunk enable listen 9997 --accept-license --answer-yes --no-prompt
./splunk start --accept-license --answer-yes --no-prompt
# Deploy detection content
cp savedsearches.conf /opt/splunk/etc/apps/search/local/
./splunk restart
```

- **Splunk Web:** `http://192.168.1.25:8000` (accessed from the Kali machine's browser)
- **Forwarder receiving:** TCP `9997` (`Settings -> Forwarding and receiving`)

### 2. Universal Forwarder (Windows Server DC `192.168.1.11`)

```powershell
msiexec /i splunkforwarder-9.x.x-x64.msi RECEIVING_SERVER="192.168.1.25:9997" WMONITORING_HOME="C:\Program Files\SplunkUniversalForwarder" /quiet AGREETOLICENSE=Yes
```

Then copy [`inputs.conf`](inputs.conf) and [`outputs.conf`](outputs.conf) into
`C:\Program Files\SplunkUniversalForwarder\etc\system\local\`
(replace `<UBUNTU_SPLUNK_IP>` with `192.168.1.25`) and restart:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart
```

### 3. Verify the pipeline

```powershell
# On the DC — should list 192.168.1.25:9997
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

```
index=main | stats count by sourcetype, host      ← run this in Splunk Web
```

If `WinEventLog:Security`, `WinEventLog:System` and
`WinEventLog:Microsoft-Windows-Sysmon/Operational` all show counts from `WIN-DC01`,
the pipeline is healthy — screenshots of these two checks go in [`../screenshots/`](../screenshots/).

> **Field-name tip:** the SPL in this repo uses standard `WinEventLog` field names
> (`EventCode`, `Account_Name`, `Source_Network_Address`, `Image`, `CommandLine`,
> `TargetFilename`…). Always confirm against one of your own events in **Splunk Web →
> Search → click an event → XML/JSON tab** — some fields (e.g. Sysmon XML) live under
> `EventData.*` depending on the TA/props configuration.
