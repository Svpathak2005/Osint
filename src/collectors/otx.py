"""
OTX (AlienVault) collector - auto-loads .env

Usage:
    python src/collectors/otx.py 8.8.8.8 1.1.1.1

Notes:
 - Reads API_KEY_OTX from .env
 - Calls AlienVault OTX v1 indicators endpoint:
   GET /api/v1/indicators/IPv4/{ip}/general
 - Writes JSONL to data/raw/otx/YYYY-MM-DD.jsonl
 - Handles simple retries and backoff
"""

from dotenv import load_dotenv
import os
import sys
import json
import time
import datetime
from pathlib import Path
import httpx

# --- locate project root and load .env explicitly (two levels up)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOTENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(DOTENV_PATH)

API_KEY = os.getenv("API_KEY_OTX")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_OTX in .env file (check .env at project root).")

# output location
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "otx"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

# HTTP client settings
TIMEOUT = 15.0
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
OTX_BASE = "https://otx.alienvault.com/api/v1"

def _sleep_backoff(backoff):
    # small jitter
    time.sleep(backoff + (0.1 * (time.time() % 1)))

def fetch_otx_ip(ip: str):
    """
    Fetch OTX general info for an IPv4 indicator:
      GET /api/v1/indicators/IPv4/{ip}/general
    Returns JSON dict on success or the raw body on 404/other.
    """
    url = f"{OTX_BASE}/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": API_KEY, "Accept": "application/json"}
    backoff = INITIAL_BACKOFF

    with httpx.Client(timeout=TIMEOUT) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 429:
                    # OTX may not frequently return 429 for small test loads, but handle anyway
                    ra = resp.headers.get("Retry-After")
                    wait = float(ra) if ra and ra.isdigit() else backoff
                    print(f"[warn] OTX 429 for {ip} (attempt {attempt}). Waiting {wait}s.")
                    _sleep_backoff(wait)
                    backoff *= 2
                    continue

                if resp.status_code == 404:
                    # indicator not present in OTX - return the response body for visibility
                    try:
                        return {"status_code": 404, "body": resp.json()}
                    except Exception:
                        return {"status_code": 404, "text": resp.text}

                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                snippet = exc.response.text[:200]
                print(f"[error] HTTP error for {ip}: {code} - {snippet}")
                if 500 <= code < 600 and attempt < MAX_RETRIES:
                    print(f"[warn] Server error, retrying after {backoff}s...")
                    _sleep_backoff(backoff)
                    backoff *= 2
                    continue
                raise
            except httpx.RequestError as exc:
                print(f"[warn] Network error for {ip}: {exc} (attempt {attempt})")
                if attempt < MAX_RETRIES:
                    _sleep_backoff(backoff)
                    backoff *= 2
                    continue
                raise
    raise RuntimeError("Unreachable code in fetch_otx_ip()")

def main():
    ips = sys.argv[1:] or ["8.8.8.8"]
    results = []

    for ip in ips:
        print(f"[info] Fetching OTX for {ip} ...")
        try:
            data = fetch_otx_ip(ip)
            out = {
                "indicator": ip,
                "type": "ipv4",
                "source": "otx",
                "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "data": data
            }
            results.append(out)
            # be polite to the API
            time.sleep(1.0)
        except Exception as e:
            print(f"[error] Failed to fetch {ip}: {e}")

    # Write appended JSONL
    if results:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            for item in results:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"[ok] Wrote {len(results)} items to {OUT_FILE}")
    else:
        print("[info] No results to write.")

if __name__ == "__main__":
    main()
