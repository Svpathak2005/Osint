"""
VirusTotal collector - auto-loads .env

Usage:
    python src/collectors/virustotal.py 8.8.8.8 1.1.1.1

Notes:
 - Uses VirusTotal v3 API (header 'x-apikey').
 - Writes results to data/raw/virustotal/YYYY-MM-DD.jsonl
 - Handles 429 (rate-limit) using Retry-After if provided.
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

API_KEY = os.getenv("API_KEY_VIRUSTOTAL")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_VIRUSTOTAL in .env file (check .env at project root).")

# output location
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "virustotal"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

# HTTP client settings
TIMEOUT = 20.0
MAX_RETRIES = 4
INITIAL_BACKOFF = 1.0  # seconds

VT_BASE = "https://www.virustotal.com/api/v3"

def _sleep_backoff(backoff):
    # small jitter to avoid strict retry storms
    time.sleep(backoff + (0.1 * (time.time() % 1)))

def fetch_vt_ip(ip: str):
    """
    Fetch IP report from VirusTotal v3:
      GET /api/v3/ip_addresses/{ip}
    Returns JSON dict on success, raises on unrecoverable error.
    """
    url = f"{VT_BASE}/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    backoff = INITIAL_BACKOFF

    with httpx.Client(timeout=TIMEOUT) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = client.get(url, headers=headers)
                # Handle 429 with optional Retry-After
                if resp.status_code == 429:
                    ra = resp.headers.get("Retry-After")
                    if ra:
                        try:
                            wait = float(ra)
                        except Exception:
                            wait = backoff
                    else:
                        wait = backoff
                    print(f"[warn] VirusTotal 429 for {ip} (attempt {attempt}). Waiting {wait}s.")
                    _sleep_backoff(wait)
                    backoff *= 2
                    continue

                # For 404, the IP may be unknown — return the body for visibility
                if resp.status_code == 404:
                    print(f"[info] VirusTotal returned 404 for {ip} (unknown to VT).")
                    try:
                        return resp.json()
                    except Exception:
                        return {"status_code": 404, "text": resp.text}

                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                body = exc.response.text[:200]
                print(f"[error] HTTP error for {ip}: {code} - {body}")
                # Retry on 5xx
                if 500 <= code < 600 and attempt < MAX_RETRIES:
                    print(f"[warn] Server error, retrying after {backoff}s...")
                    _sleep_backoff(backoff)
                    backoff *= 2
                    continue
                # Unrecoverable 4xx other than 429/404 — stop and raise
                raise
            except httpx.RequestError as exc:
                print(f"[warn] Network error for {ip}: {exc} (attempt {attempt})")
                if attempt < MAX_RETRIES:
                    _sleep_backoff(backoff)
                    backoff *= 2
                    continue
                raise
    raise RuntimeError("Unreachable code in fetch_vt_ip()")

def main():
    ips = sys.argv[1:] or ["8.8.8.8"]
    results = []

    for ip in ips:
        print(f"[info] Fetching VirusTotal for {ip} ...")
        try:
            data = fetch_vt_ip(ip)
            out = {
                "indicator": ip,
                "type": "ipv4",
                "source": "virustotal",
                "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "data": data
            }
            results.append(out)
            # be polite to the API
            time.sleep(1.0)
        except Exception as e:
            print(f"[error] Failed to fetch {ip}: {e}")

    # Write results appended to JSONL
    if results:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            for item in results:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"[ok] Wrote {len(results)} items to {OUT_FILE}")
    else:
        print("[info] No results to write.")

if __name__ == "__main__":
    main()
