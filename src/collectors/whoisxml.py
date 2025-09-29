from dotenv import load_dotenv
import os, sys, httpx, json, datetime, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("API_KEY_WHOISXML")
if not API_KEY:
    raise RuntimeError("Missing API_KEY_WHOISXML in .env")

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "whoisxml"
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = RAW_DIR / f"{datetime.date.today()}.jsonl"

def fetch_whois(domain: str):
    url = "https://whoisxmlapi.com/whoisserver/WhoisService"
    params = {"apiKey": API_KEY, "domainName": domain, "outputFormat": "JSON"}
    r = httpx.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()

def main():
    domains = sys.argv[1:] or ["example.com"]
    with open(OUT_FILE, "a") as f:
        for d in domains:
            print(f"[info] Fetching WHOISXML for {d}")
            try:
                data = fetch_whois(d)
                out = {
                    "indicator": d,
                    "type": "domain",
                    "source": "whoisxml",
                    "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
                    "data": data
                }
                f.write(json.dumps(out) + "\n")
            except Exception as e:
                print(f"[error] {e}")

if __name__ == "__main__":
    main()
