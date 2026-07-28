#!/usr/bin/env python3
"""
ai_query_generator.py

Natural language -> SIEM query translator (Logscale / Splunk SPL / Graylog-Lucene).

Given a plain-English detection idea (e.g. "detect lateral movement via RDP
from a workstation to a server"), calls an LLM (default: Google Gemini) to
produce a candidate query in the target query language, using a handful of
real queries from this repo as few-shot examples so the style/fields match
what's already in use.

IMPORTANT
---------
Generated queries are a DRAFT, not a production-ready detection.
Always validate field names against your actual log schema, test against
historical data, and tune for false positives before deploying as an alert.
This tool is decision support for an analyst, not a replacement for one.

Usage
-----
    export GEMINI_API_KEY="..."
    python ai_query_generator.py --platform logscale --prompt "detect a new scheduled task created remotely"
    python ai_query_generator.py --platform splunk --prompt "detect impossible travel logins" --explain

Requirements
------------
    pip install -r requirements.txt
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests

GEMINI_MODEL = "gemini-3.5-flash"
GEMINI_ENDPOINT = (
    f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
)

SUPPORTED_PLATFORMS = ("logscale", "splunk", "graylog")

SYSTEM_PROMPT = """You are a detection engineering assistant for a SOC / threat hunting team.
You translate a plain-English detection idea into a single, syntactically correct query
for the requested log platform ({platform}).

Rules:
- Output ONLY valid {platform} query syntax in the "query" field. No markdown fences.
- Base field names and style on the example queries provided, when relevant.
- If the request is ambiguous, make a reasonable assumption and state it in "assumptions".
- For "mitre_technique", output ONLY the technique ID (e.g. "T1021.001") chosen from the
  reference list below, or null if none of the listed techniques genuinely applies.
  Do not invent an ID that is not in this list - it will be rejected and discarded.
- Always include a "caveats" field listing at least one thing the analyst must verify
  before using this in production (e.g. field name mismatch, expected log volume, tuning needed).
- Respond with a single JSON object only, matching this schema:
  {{"query": "...", "assumptions": "...", "mitre_technique": "...", "caveats": "..."}}

Reference technique list (id | name | tactic) - pick from this list only, or null:
{mitre_list}
"""


def load_examples(path: Path, platform: str, limit: int = 5):
    """Load a few real queries as few-shot context, if an examples file exists."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [ex for ex in data.get(platform, [])][:limit]


def load_mitre_reference(path: Path):
    """Load the curated MITRE ATT&CK technique list used to ground mitre_technique output."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("techniques", [])


def format_mitre_list(techniques: list) -> str:
    if not techniques:
        return "(no reference list loaded - always respond with mitre_technique: null)"
    return "\n".join(f"- {t['id']} | {t['name']} | {t['tactic']}" for t in techniques)


def validate_mitre_technique(value, techniques: list):
    """Return value unchanged if it's a real ID from the reference list, else None + warning."""
    if value is None:
        return None
    valid_ids = {t["id"] for t in techniques}
    if value in valid_ids:
        return value
    print(
        f"WARNING: model returned MITRE technique '{value}', which is not in the "
        f"reference list - discarding it (treating as null) to avoid a hallucinated ID."
    )
    return None


def build_prompt(user_prompt: str, platform: str, examples: list) -> str:
    parts = [f"Target platform: {platform}", f"Detection idea: {user_prompt}"]
    if examples:
        parts.append("\nExisting query examples for style/field reference:")
        for ex in examples:
            parts.append(
                f"- Description: {ex.get('description', '')}\n  Query: {ex.get('query', '')}"
            )
    parts.append("\nRespond with the JSON object described in the system prompt.")
    return "\n".join(parts)


def call_gemini(system_prompt: str, user_prompt: str, api_key: str) -> str:
    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }
    resp = requests.post(f"{GEMINI_ENDPOINT}?key={api_key}", json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


def main():
    parser = argparse.ArgumentParser(
        description="NL -> SIEM query generator (Logscale/Splunk/Graylog)"
    )
    parser.add_argument("--platform", choices=SUPPORTED_PLATFORMS, required=True)
    parser.add_argument("--prompt", required=True, help="Plain-English detection idea")
    parser.add_argument(
        "--examples-file", default="examples.json", help="Few-shot examples file"
    )
    parser.add_argument(
        "--mitre-file", default="mitre_reference.json", help="Curated MITRE ATT&CK reference file"
    )
    parser.add_argument(
        "--explain", action="store_true", help="Also print assumptions/caveats/MITRE mapping"
    )
    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        sys.exit("ERROR: set the GEMINI_API_KEY environment variable first.")

    examples = load_examples(Path(args.examples_file), args.platform)
    techniques = load_mitre_reference(Path(args.mitre_file))
    system_prompt = SYSTEM_PROMPT.format(
        platform=args.platform, mitre_list=format_mitre_list(techniques)
    )
    user_prompt = build_prompt(args.prompt, args.platform, examples)

    raw = call_gemini(system_prompt, user_prompt, api_key)

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        print("WARNING: model did not return clean JSON, printing raw output:\n")
        print(raw)
        return

    print("\n--- Generated query (review before use) ---")
    print(result.get("query", "").strip())

    if args.explain:
        validated_mitre = validate_mitre_technique(result.get("mitre_technique"), techniques)
        print("\n--- Assumptions ---")
        print(result.get("assumptions", "-"))
        print("\n--- MITRE ATT&CK (validated against reference list) ---")
        print(validated_mitre or "null (none applied, or model's answer was discarded)")
        print("\n--- Caveats (verify before deploying) ---")
        print(result.get("caveats", "-"))


if __name__ == "__main__":
    main()
