"""
AbuseIPDB collector - auto-loads .env

Usage:
    python src/collectors/abuseipdb.py 8.8.8.8 1.1.1.1

What it does:
 - loads API_KEY_ABUSEIPDB from project .env
 - calls AbuseIPDB /check endpoint for each IP
 - handles retries and 429 with backoff
 - writes results to data/raw/abuseipdb/YYYY-MM-DD.jsonl
"""

from dotenv import load_dotenv
import os
import sys
import json
import time
import datetime
from pathlib import Path
import httpx

# --- locate project root and load .env explicitly (two levels up from this file)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOTENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(DOTENV_PATH)

API_KEY = os.getenv("API_KEY_ABUSEIPDB")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_ABUSEIPDB in .env file (check .env at project root).")

# output location
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "abuseipdb"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

# HTTP client settings
TIMEOUT = 15.0
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds

def fetch_abuseipdb(ip: str, max_age_days: int = 90):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days)}
    backoff = INITIAL_BACKOFF

    with httpx.Client(timeout=TIMEOUT) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = client.get(url, headers=headers, params=params)
                if resp.status_code == 429:
                    print(f"[warn] AbuseIPDB 429 for {ip} (attempt {attempt}). Backing off {backoff}s.")
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                resp.raise_for_status()
                # abuseipdb returns top-level JSON with 'data' key
                return resp.json()
            except httpx.HTTPStatusError as exc:
                print(f"[error] HTTP error for {ip}: {exc.response.status_code} - {exc.response.text[:200]}")
                if 500 <= exc.response.status_code < 600 and attempt < MAX_RETRIES:
                    time.sleep(backoff); backoff *= 2
                    continue
                raise
            except httpx.RequestError as exc:
                print(f"[warn] Network error for {ip}: {exc} (attempt {attempt})")
                if attempt < MAX_RETRIES:
                    time.sleep(backoff); backoff *= 2
                    continue
                raise
    raise RuntimeError("Unreachable code in fetch_abuseipdb()")

def main():
    ips = sys.argv[1:] or ["8.8.8.8"]
    results = []
    for ip in ips:
        print(f"[info] Fetching AbuseIPDB for {ip} ...")
        try:
            raw = fetch_abuseipdb(ip)
            data = raw.get("data", raw)  # prefer "data" key
            out = {
                "indicator": ip,
                "type": "ipv4",
                "source": "abuseipdb",
                "fetched_at": datetime.datetime.utcnow().isoformat() + "Z",
                "data": data
            }
            results.append(out)
            time.sleep(1.0)
        except Exception as e:
            print(f"[error] Failed to fetch {ip}: {e}")

    # write JSONL
    if results:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            for item in results:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"[ok] Wrote {len(results)} items to {OUT_FILE}")
    else:
        print("[info] No results to write.")

if __name__ == "__main__":
    main()
