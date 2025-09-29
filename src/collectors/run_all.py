import subprocess

sources = ["shodan", "abuseipdb","virustotal","otx"]
for src in sources:
    print(f"Running collector: {src}")
    subprocess.run(["python", f"src/collectors/{src}.py"])
