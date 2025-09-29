"""
Censys collector - supports Personal Access Token or ID+Secret.
Writes JSONL to data/raw/censys/YYYY-MM-DD.jsonl
"""
from dotenv import load_dotenv
import os, sys, json, time, datetime
from pathlib import Path
import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

TOKEN = os.getenv("CENSYS_API_TOKEN")
API_ID = os.getenv("CENSYS_API_ID")
API_SECRET = os.getenv("CENSYS_API_SECRET")

if not (TOKEN or (API_ID and API_SECRET)):
    raise RuntimeError("Missing Censys credentials in .env (CENSYS_API_TOKEN or CENSYS_API_ID+CENSYS_API_SECRET)")

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "censys"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

TIMEOUT = 20.0
MAX_RETRIES = 3
BACKOFF = 1.0
BASE = "https://search.censys.io/api/v2"

def fetch_censys(ip: str):
    url = f"{BASE}/hosts/{ip}"
    headers = {"Accept": "application/json"}
    backoff = BACKOFF

    with httpx.Client(timeout=TIMEOUT) as client:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if TOKEN:
                    headers["Authorization"] = f"Bearer {TOKEN}"
                    resp = client.get(url, headers=headers)
                else:
                    resp = client.get(url, auth=(API_ID, API_SECRET))
                if resp.status_code == 429:
                    wait = float(resp.headers.get("Retry-After", backoff))
                    print(f"[warn] Censys 429 for {ip}, waiting {wait}s")
                    time.sleep(wait); backoff *= 2
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.RequestError as exc:
                print(f"[warn] Network error for censys {ip}: {exc} (attempt {attempt})")
                if attempt < MAX_RETRIES:
                    time.sleep(backoff); backoff *= 2
                    continue
                raise
            except httpx.HTTPStatusError as exc:
                print(f"[error] HTTP error for censys {ip}: {exc.response.status_code}")
                raise

def main():
    ips = sys.argv[1:] or ["8.8.8.8"]
    results = []
    for ip in ips:
        print(f"[info] Fetching Censys for {ip} ...")
        try:
            data = fetch_censys(ip)
            results.append({
                "indicator": ip,
                "type": "ipv4",
                "source": "censys",
                "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "data": data
            })
            time.sleep(1)
        except Exception as e:
            print(f"[error] censys fetch failed for {ip}: {e}")

    if results:
        with open(OUT_FILE, "a", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[ok] Wrote {len(results)} items to {OUT_FILE}")
    else:
        print("[info] No censys results to write.")

if __name__ == "__main__":
    main()
