# 🔍 Investigation Queries (Wazuh Dashboard)

These are the queries an analyst runs when working an alert in this lab.
Syntax is **OpenSearch Dashboards Query Language (DQL)** as used by the Wazuh
dashboard's search bar. Each file covers one attack class and contains:

1. **Detection query** — confirms the alert (rule-based)
2. **Raw telemetry query** — shows the underlying events (evidence)
3. **Scoping / pivot queries** — "what else touched this host/account/IP?"
4. **Expected output** — what you should see if the simulation succeeded

## How to run them

1. Open `https://192.168.1.25` → **Threat intelligence → Security Events** (or **Explore → Discover**).
2. Set the time range to cover your simulation window (e.g. *Last 30 minutes*).
3. Paste the query into the search bar (DQL) or build it with the filter pills.
4. Open an event's **JSON tab** to confirm field names on your version before relying on them.

> **Pro tip recruiters like:** copy field names from the JSON of a real event rather than
> memorizing them — it shows you work with actual telemetry, not copied blog posts.

## Query index

| File | Attack class | ATT&CK tactic |
|------|--------------|---------------|
| [credential-access.md](credential-access.md) | Brute force, password spray, valid account | Credential Access |
| [execution.md](execution.md) | Suspicious PowerShell, malware delivery | Execution |
| [persistence.md](persistence.md) | Scheduled tasks, Run-key autoruns | Persistence |
| [defense-evasion.md](defense-evasion.md) | Log clearing, agent tampering | Defense Evasion |
| [discovery.md](discovery.md) | Host/account recon command clusters | Discovery |

## Useful building blocks

| Goal | DQL fragment |
|------|--------------|
| One rule ID | `rule.id : 100101` |
| One agent | `agent.name : WIN11-PRO` |
| One source IP | `data.win.eventdata.ipAddress : 192.168.1.8` |
| One event ID | `data.win.system.eventID : 4625` |
| Several event IDs | `data.win.system.eventID : (4625 or 4624)` |
| Free-text command | `data.win.eventdata.commandLine : *downloadstring*` |
| MITRE group | `rule.mitre.id : T1110.001` |
