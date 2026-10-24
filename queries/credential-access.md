# Credential Access — Brute Force & Valid Account (SIM-02)

**ATT&CK:** T1110.001 (Brute Force: Password Guessing) · T1078 (Valid Accounts)
**Events:** Windows Security 4625 (failed logon) → 4624 (successful logon)
**Custom rules:** `100100`, `100101`, `100102`

---

## 1. Detection query — did the custom rule fire?

```
rule.id : (100101 or 100102)
```

Expected: one `100101` alert (brute-force burst) and — if the attack succeeded —
one `100102` critical alert (successful logon after the burst).

## 2. Raw telemetry — failed logons during the attack window

```
data.win.system.eventID : 4625 AND data.win.eventdata.ipAddress : 192.168.1.8
```

Key fields to extract from each event:

| Field | Meaning | Evidence value |
|-------|---------|----------------|
| `data.win.eventdata.targetUserName` | Account targeted | e.g. `testuser`, `Administrator` |
| `data.win.eventdata.ipAddress` | Source of the attempt | `192.168.1.8` (Kali) |
| `data.win.eventdata.logonType` | Logon channel | `3` (SMB/network), `10` (RDP) |
| `data.win.eventdata.workstationName` | Reported workstation | attacker-supplied name |
| `timestamp` | When | attack window |

## 3. Pivot — did the attacker succeed?

```
data.win.system.eventID : 4624 AND data.win.eventdata.ipAddress : 192.168.1.8
```

A `4624` with the same source IP **after** the 4625 storm = compromise confirmed.
Note the `logonType` and `targetUserName` — that is the account to disable first.

## 4. Scoping — has this account/host been noisy before?

```
data.win.eventdata.targetUserName : testuser AND data.win.system.eventID : (4625 or 4624)
```

```
agent.name : WIN11-PRO AND rule.groups : brute_force
```

## 5. Correlation table for the report

| Status | Account | Source IP | Count | Time window |
|--------|---------|-----------|-------|-------------|
| Failed logon (4625) | … | … | … | … |
| Successful logon (4624) | … | … | … | … |

*(Fill this from query results — it becomes the evidence table in your incident report.)*

## Expected output (shape)

```json
{
  "rule": { "id": "100101", "level": 12, "description": "Possible brute-force attack: ...", "mitre": {"id": "T1110.001"} },
  "agent": { "name": "WIN11-PRO", "ip": "192.168.1.11" },
  "data": {
    "win": {
      "system": { "eventID": "4625", "computer": "WIN11-PRO" },
      "eventdata": { "targetUserName": "testuser", "ipAddress": "192.168.1.8", "logonType": "3" }
    }
  },
  "timestamp": "2026-10-24T12:34:56.789+0000"
}
```
