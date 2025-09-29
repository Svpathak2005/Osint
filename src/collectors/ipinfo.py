from dotenv import load_dotenv
import os, sys, httpx, json, datetime, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("API_KEY_IPINFO")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_IPINFO in .env")

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "ipinfo"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

def fetch_ip(ip: str):
    url = f"https://ipinfo.io/{ip}"
    params = {"token": API_KEY}
    r = httpx.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()

def main():
    ips = sys.argv[1:] or ["8.8.8.8"]
    with open(OUT_FILE, "a") as f:
        for ip in ips:
            print(f"[info] Fetching IPinfo for {ip}")
            try:
                data = fetch_ip(ip)
                out = {
                    "indicator": ip,
                    "type": "ipv4",
                    "source": "ipinfo",
                    "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                    "data": data
                }
                f.write(json.dumps(out) + "\n")
            except Exception as e:
                print(f"[error] {e}")

if __name__ == "__main__":
    main()
