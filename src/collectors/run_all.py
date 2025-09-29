import subprocess
import sys

sources = ["shodan", "abuseipdb", "virustotal", "otx", "malwarebazaar", "greynoise", "censys", "urlhaus"]
for src in sources:
    print(f"Running collector: {src}")
    subprocess.run([sys.executable, f"src/collectors/{src}.py"])
