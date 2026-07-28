<#
.SYNOPSIS
    Natural language -> SIEM query translator (Logscale / Splunk SPL / Graylog-Lucene).

.DESCRIPTION
    PowerShell port of ai_query_generator.py. Given a plain-English detection idea
    (e.g. "detect a new scheduled task created remotely"), calls an LLM (Google Gemini
    by default) to produce a candidate query in the target query language, using real
    queries from examples.json as few-shot style/field reference. Any MITRE ATT&CK
    mapping is constrained to the techniques listed in mitre_reference.json - an ID
    outside that list is treated as a hallucination and discarded rather than trusted.

    IMPORTANT
    ---------
    Generated queries are a DRAFT, not a production-ready detection. Always validate
    field names against your actual log schema, test against historical data, and
    tune for false positives before deploying as an alert.

.PARAMETER Platform
    Target query platform: logscale, splunk, or graylog.

.PARAMETER Prompt
    Plain-English detection idea.

.PARAMETER ExamplesFile
    Path to the few-shot examples file (default examples.json).

.PARAMETER MitreFile
    Path to the curated MITRE ATT&CK reference file (default mitre_reference.json).

.PARAMETER ApiKey
    Gemini API key. Defaults to $env:GEMINI_API_KEY.

.PARAMETER Model
    Gemini model name. Defaults to gemini-3.5-flash.

.PARAMETER Explain
    Also print assumptions, MITRE mapping, and caveats.

.EXAMPLE
    .\ai_query_generator.ps1 -Platform logscale -Prompt "detect a new scheduled task created remotely" -Explain
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("logscale", "splunk", "graylog")]
    [string]$Platform,

    [Parameter(Mandatory = $true)]
    [string]$Prompt,

    [string]$ExamplesFile = "examples.json",
    [string]$MitreFile = "mitre_reference.json",
    [string]$ApiKey = $env:GEMINI_API_KEY,
    [string]$Model = "gemini-3.5-flash",
    [switch]$Explain
)

if (-not $ApiKey) {
    throw "No API key provided. Set `$env:GEMINI_API_KEY or pass -ApiKey."
}

function Get-FewShotExamples {
    param([string]$Path, [string]$Platform, [int]$Limit = 5)
    if (-not (Test-Path $Path)) { return @() }
    $data = Get-Content -Path $Path -Raw | ConvertFrom-Json
    $platformExamples = $data.$Platform
    if (-not $platformExamples) { return @() }
    return $platformExamples | Select-Object -First $Limit
}

function Get-MitreReference {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @() }
    $data = Get-Content -Path $Path -Raw | ConvertFrom-Json
    return $data.techniques
}

function Format-MitreList {
    param([array]$Techniques)
    if (-not $Techniques -or $Techniques.Count -eq 0) {
        return "(no reference list loaded - always respond with mitre_technique: null)"
    }
    return ($Techniques | ForEach-Object { "- $($_.id) | $($_.name) | $($_.tactic)" }) -join "`n"
}

function Test-MitreTechnique {
    param($Value, [array]$Techniques)
    if (-not $Value -or $Value -eq "null") { return $null }
    $validIds = @($Techniques | ForEach-Object { $_.id })
    if ($validIds -contains $Value) { return $Value }
    Write-Warning "Model returned MITRE technique '$Value', which is not in the reference list - discarding it (treating as null) to avoid a hallucinated ID."
    return $null
}

# --- Load context ---
$examples = Get-FewShotExamples -Path $ExamplesFile -Platform $Platform
$techniques = @(Get-MitreReference -Path $MitreFile)
$mitreListText = Format-MitreList -Techniques $techniques

# --- Build prompts ---
$systemPrompt = @"
You are a detection engineering assistant for a SOC / threat hunting team.
You translate a plain-English detection idea into a single, syntactically correct query
for the requested log platform ($Platform).

Rules:
- Output ONLY valid $Platform query syntax in the "query" field. No markdown fences.
- Base field names and style on the example queries provided, when relevant.
- If the request is ambiguous, make a reasonable assumption and state it in "assumptions".
- For "mitre_technique", output ONLY the technique ID (e.g. "T1021.001") chosen from the
  reference list below, or null if none of the listed techniques genuinely applies.
  Do not invent an ID that is not in this list - it will be rejected and discarded.
- Always include a "caveats" field listing at least one thing the analyst must verify
  before using this in production (e.g. field name mismatch, expected log volume, tuning needed).
- Respond with a single JSON object only, matching this schema:
  {"query": "...", "assumptions": "...", "mitre_technique": "...", "caveats": "..."}

Reference technique list (id | name | tactic) - pick from this list only, or null:
$mitreListText
"@

$userPromptLines = @("Target platform: $Platform", "Detection idea: $Prompt")
if ($examples.Count -gt 0) {
    $userPromptLines += ""
    $userPromptLines += "Existing query examples for style/field reference:"
    foreach ($ex in $examples) {
        $userPromptLines += "- Description: $($ex.description)`n  Query: $($ex.query)"
    }
}
$userPromptLines += ""
$userPromptLines += "Respond with the JSON object described in the system prompt."
$userPrompt = $userPromptLines -join "`n"

# --- Call Gemini ---
$bodyObj = @{
    system_instruction = @{ parts = @(@{ text = $systemPrompt }) }
    contents           = @(@{ role = "user"; parts = @(@{ text = $userPrompt }) })
    generationConfig   = @{ temperature = 0.2 }
}
$body = $bodyObj | ConvertTo-Json -Depth 10

# API key sent as a header rather than a URL query parameter, so it doesn't
# end up verbatim in any proxy/TLS-inspection access logs.
$uri = "https://generativelanguage.googleapis.com/v1beta/models/${Model}:generateContent"
try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/json" -Headers @{ "x-goog-api-key" = $ApiKey } -ErrorAction Stop
}
catch {
    throw "Gemini API call failed: $($_.Exception.Message)"
}
$rawText = $response.candidates[0].content.parts[0].text

try {
    $result = $rawText | ConvertFrom-Json
}
catch {
    Write-Warning "Model did not return clean JSON, printing raw output:"
    Write-Output $rawText
    return
}

# --- Output ---
Write-Host "`n--- Generated query (review before use) ---"
Write-Host $result.query

if ($Explain) {
    $validatedMitre = Test-MitreTechnique -Value $result.mitre_technique -Techniques $techniques

    Write-Host "`n--- Assumptions ---"
    Write-Host $result.assumptions

    Write-Host "`n--- MITRE ATT&CK (validated against reference list) ---"
    if ($validatedMitre) {
        Write-Host $validatedMitre
    }
    else {
        Write-Host "null (none applied, or model's answer was discarded)"
    }

    Write-Host "`n--- Caveats (verify before deploying) ---"
    Write-Host $result.caveats
}
