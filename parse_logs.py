import re
import requests
import time

API_KEY = "API_KEY_HERE"

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]
        return malicious, suspicious
    else:
        return None, None

# Step 1: Read log file
with open("sample_log.txt", "r") as file:
    logs = file.readlines()

# Step 2: Extract unique IP addresses
ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
found_ips = set()

for line in logs:
    ips = re.findall(ip_pattern, line)
    found_ips.update(ips)

# Step 3: Analyze and build report content
report_lines = []
report_lines.append("# Log Analysis Report\n")
report_lines.append("## Unique IPs Extracted\n")
for ip in found_ips:
    report_lines.append(f"- {ip}")
report_lines.append("\n## VirusTotal Analysis\n")
report_lines.append("| IP Address       | Malicious | Suspicious | Status      |")
report_lines.append("|------------------|-----------|------------|-------------|")

print("Analyzing IPs and building report...\n")
for ip in found_ips:
    malicious, suspicious = check_ip_virustotal(ip)
    if malicious is not None:
        status = "CLEAN"
        if malicious > 0 or suspicious > 0:
            status = "⚠️ MALICIOUS"
        report_lines.append(f"| {ip:16} | {malicious:^9} | {suspicious:^10} | {status:11} |")
    else:
        report_lines.append(f"| {ip:16} |   ERROR   |   ERROR   | FAILED TO CHECK |")
    time.sleep(15)  # VirusTotal free-tier rate limit

# Step 4: Add time to report

from datetime import datetime

# Generate timestamp
timestamp = datetime.now().strftime("%Y-%m-%d %I-%M%p")

# Add timestamp to top of the report
report_lines.insert(0, f"_Generated: {timestamp}_\n")
report_lines.insert(0, "# Log Analysis Report\n")

# Save file with timestamp in filename
filename = f"report_{timestamp}.md"
with open(filename, "w", encoding="utf-8") as report_file:
    report_file.write("\n".join(report_lines))

print(f"\n✅ Report saved as '{filename}'")
