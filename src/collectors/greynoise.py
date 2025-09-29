"""
Greynoise collector - auto-loads .env and writes JSONL to data/raw/greynoise/YYYY-MM-DD.jsonl
"""
from dotenv import load_dotenv
import os, sys, json, time, datetime
from pathlib import Path
import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("API_KEY_GREYNOISE")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_GREYNOISE in .env")

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "greynoise"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

TIMEOUT = 15.0
MAX_RETRIES = 3
BACKOFF = 1.0

def fetch_greynoise(ip: str):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"Accept": "application/json", "key": API_KEY}
    backoff = BACKOFF

    with httpx.Client(timeout=TIMEOUT) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = client.get(url, headers=headers)
                if resp.status_code == 429:
                    wait = float(resp.headers.get("Retry-After", backoff))
                    print(f"[warn] Greynoise 429 for {ip}, waiting {wait}s")
                    time.sleep(wait)
                    backoff *= 2
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.RequestError as exc:
                print(f"[warn] Network error for greynoise {ip}: {exc} (attempt {attempt})")
                if attempt < MAX_RETRIES:
                    time.sleep(backoff); backoff *= 2
                    continue
                raise
            except httpx.HTTPStatusError as exc:
                print(f"[error] HTTP error for greynoise {ip}: {exc.response.status_code}")
                raise

def main():
    ips = sys.argv[1:] or ["8.8.8.8"]
    results = []
    for ip in ips:
        print(f"[info] Fetching GreyNoise for {ip} ...")
        try:
            data = fetch_greynoise(ip)
            results.append({
                "indicator": ip,
                "type": "ipv4",
                "source": "greynoise",
                "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "data": data
            })
            time.sleep(1)
        except Exception as e:
            print(f"[error] greynoise fetch failed for {ip}: {e}")

    if results:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[ok] Wrote {len(results)} items to {OUT_FILE}")
    else:
        print("[info] No greynoise results to write.")

if __name__ == "__main__":
    main()
