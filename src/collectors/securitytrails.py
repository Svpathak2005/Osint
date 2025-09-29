from dotenv import load_dotenv
import os, sys, httpx, json, datetime, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("API_KEY_SECURITYTRAILS")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_SECURITYTRAILS in .env")

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "securitytrails"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

def fetch_domain(domain: str):
    url = f"https://api.securitytrails.com/v1/domain/{domain}"
    headers = {"APIKEY": API_KEY}
    r = httpx.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()

def main():
    domains = sys.argv[1:] or ["example.com"]
    with open(OUT_FILE, "a") as f:
        for d in domains:
            print(f"[info] Fetching SecurityTrails for {d}")
            try:
                data = fetch_domain(d)
                out = {
                    "indicator": d,
                    "type": "domain",
                    "source": "securitytrails",
                    "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                    "data": data
                }
                f.write(json.dumps(out) + "\n")
            except Exception as e:
                print(f"[error] {e}")

if __name__ == "__main__":
    main()
