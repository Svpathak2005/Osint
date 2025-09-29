"""
URLhaus collector - uses URLhaus API with Auth-Key header.
Writes JSONL to data/raw/urlhaus/YYYY-MM-DD.jsonl
"""
from dotenv import load_dotenv
import os, sys, json, time, datetime
from pathlib import Path
import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")
if not AUTH_KEY:
    raise RuntimeError("Missing URLHAUS_AUTH_KEY in .env")

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "urlhaus"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

TIMEOUT = 20.0
MAX_RETRIES = 3
BACKOFF = 1.0
BASE = "https://urlhaus-api.abuse.ch"

def fetch_urlhaus_lookup(url_value: str):
    api = f"{BASE}/v1/url/"
    headers = {"Accept": "application/json", "Auth-Key": AUTH_KEY}
    backoff = BACKOFF

    with httpx.Client(timeout=TIMEOUT) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = client.post(api, headers=headers, data={"url": url_value})
                if resp.status_code == 429:
                    wait = float(resp.headers.get("Retry-After", backoff))
                    print(f"[warn] URLhaus 429, waiting {wait}s")
                    time.sleep(wait); backoff *= 2
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.RequestError as exc:
                print(f"[warn] Network error for urlhaus {url_value}: {exc} (attempt {attempt})")
                if attempt < MAX_RETRIES:
                    time.sleep(backoff); backoff *= 2
                    continue
                raise
            except httpx.HTTPStatusError as exc:
                print(f"[error] HTTP error urlhaus {url_value}: {exc.response.status_code}")
                raise

def main():
    inputs = sys.argv[1:] or ["https://example.com/malicious"]
    results = []
    for item in inputs:
        print(f"[info] Fetching URLhaus for {item} ...")
        try:
            data = fetch_urlhaus_lookup(item)
            results.append({
                "indicator": item,
                "type": "url",
                "source": "urlhaus",
                "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "data": data
            })
            time.sleep(1)
        except Exception as e:
            print(f"[error] urlhaus fetch failed for {item}: {e}")

    if results:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[ok] Wrote {len(results)} items to {OUT_FILE}")
    else:
        print("[info] No urlhaus results to write.")

if __name__ == "__main__":
    main()
