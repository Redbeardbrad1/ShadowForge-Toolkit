import requests
import json
import os
from termcolor import colored

def grok_suggest(scan_data: dict, api_key: str = None) -> str:
    if not api_key:
        api_key = os.getenv("GROK_API_KEY")
        if not api_key:
            return colored("[!] GROK_API_KEY not set – grab at https://x.ai/api", "red")

    url = "https://api.x.ai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    prompt = f"""
Elite red-team AI forged in ranch fire.
Raw scan data below. Return ONLY top 3 exploits — exact format, no fluff:

1. CVE-XXXX-XXXX | confidence: high/medium/low | payload: shadowforge reverse_tcp LHOST LPORT
2. ...
3. ...

Scan JSON:
{json.dumps(scan_data, indent=2)}
"""

    payload = {
        "model": "grok-4-1-fast",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3
    }

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=20)
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"]
        print(colored("\nGROK EXPLOIT SUGGESTIONS FIRE\n", "red", attrs=["bold"]))
        print(raw)
        return raw
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            print(colored("[!] 429 hit – launch day tax. Wait 1-2 min & retry or upgrade key for Grok 4.1 fast muscle", "yellow"))
        else:
            print(colored(f"[!] Grok error: {e}", "yellow"))
        return f"Error: {e}"