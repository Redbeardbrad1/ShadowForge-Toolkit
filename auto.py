import argparse
import os
import time
import random
import requests
from dotenv import load_dotenv
from modules.ai_suggest import grok_suggest  # we'll upgrade this file next

# Load .env (add to .gitignore if not already)
load_dotenv()

# Central Grok caller with exponential back-off + paid-key support
def grok_suggest_robust(scan_data):
    api_key = os.getenv("GROK_API_KEY")  # drop your paid key in .env later
    if not api_key:
        print("[-] No GROK_API_KEY in .env → falling back to free tier (429s incoming)")
    
    url = "https://api.x.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}" if api_key else "",
        "Content-Type": "application/json"
    }
    payload = {
        "messages": [
            {"role": "system", "content": "You are a ruthless but ethical penetration tester. Suggest only real, high-impact exploits for the exact versions found."},
            {"role": "user", "content": f"Scan data: {scan_data}\n\nSuggest top 3 exploits with public PoC links or payloads. No fluff."}
        ],
        "model": "grok-4",
        "temperature": 0.2
    }

    for attempt in range(8):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=30)
            if r.status_code == 200:
                response = r.json()["choices"][0]["message"]["content"]
                print("[+] Grok-4 dropped pure blood:")
                print(response)
                return response
            elif r.status_code == 429:
                wait = (2 ** attempt) + random.uniform(0, 1)
                print(f"[!] 429 – rate limit. Sleeping {wait:.1f}s (attempt {attempt+1}/8)")
                time.sleep(wait)
            else:
                print(f"[!] HTTP {r.status_code} – {r.text}")
                return None
        except Exception as e:
            print(f"[!] Request failed: {e}")
            time.sleep(2 ** attempt)
    print("[!] Grok still choking after 8 retries – upgrade key at https://x.ai/api")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShadowForge Auto-Chain – Scan → AI → Blood")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ai", action="store_true", help="Unleash Grok-4 exploit suggestions")
    args = parser.parse_args()

    from modules.recon import run_nmap   # ← moved inside main (dynamic import fixes any circular bs)

    print(f"[+] Scanning {args.target}...")
    scan_data = run_nmap(args.target)
    if not scan_data or scan_data.get("status") == "down":
        print("[-] Target down or blocked – aborting chain.")
        exit(1)

    if args.ai:
        print("[+] Asking Grok-4 for blood...")
        grok_suggest_robust(scan_data)

    print("[+] Auto chain complete – real recon + AI blood flowing.")