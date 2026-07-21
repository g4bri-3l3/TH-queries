# What

A list of queries to detect and hunt for threats written mostly for Logscale/Graylog (the ones for Graylog could be used with Splunk/Lucene based systems, too).

NB: I'm converting the queries from old language to Logscale language in free time. If you encounter any issue, please ping me. Also let me know if you are interested in knowledge exchange!

# How

- For Splunk: just copy-paste it
- For Logscale: just copy-paste it
- For Graylog: I'm assuming you are using winlogbeat for shipping logs from Windows boxes here. Just copy-paste the queries in the search bar or use them to create custom alerts (for instance: "alert me when you see a domain admin change").

## AI-Assisted Triage

`ai_alert_triage.ps1` sends RTR-collected telemetry (process list, netstat,
parent-process chain, etc.) to an LLM (Gemini by default) and returns a quick
summary, a likely MITRE ATT&CK mapping, a suggested severity, and a
suggested next step.

> **Decision support only.** No containment action is taken
> automatically - no host isolation, no process kill, no account changes. An
> analyst must review the output before acting on it.

### Setup

```powershell
$env:GEMINI_API_KEY = "..."
. .\ai_alert_triage.ps1
```

### Usage

```powershell
$ps = Invoke-FalconRtr -Command ps -HostId $hostId
$result = Invoke-AITriage -Telemetry ($ps | Out-String)
$result | Format-List
```

Works with any text blob from RTR/PSFalcon (process list, netstat output,
registry run keys, etc.) - not just `ps`.
