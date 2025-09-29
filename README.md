# Threat Aggregation Lab (Live Collectors)

This version includes **live collectors** for Shodan and AbuseIPDB.

## Setup
1. Create venv & install requirements:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy `.env.example` → `.env` and paste your API keys.

3. Run collectors:
   ```bash
   python src/collectors/shodan.py 8.8.8.8
   python src/collectors/abuseipdb.py 8.8.8.8
   python src/collectors/run_all.py
   ```

Raw results will appear under `data/raw/<source>/<date>.jsonl`
