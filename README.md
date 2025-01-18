# -Log-File-Analyzer-for-Intrusion-Detection
This project processes and analyzes system log files to detect potential security threats, such as unauthorized access attempts, suspicious login activities, and brute-force attacks. It uses log parsing, pattern matching, and basic statistical analysis to identify anomalies
import re
from collections import defaultdict
import datetime

# Function to parse log files
def parse_logs(log_file):
    log_entries = []
    with open(log_file, 'r') as file:
        for line in file:
            log_entries.append(line.strip())
    return log_entries

# Function to extract IP addresses from logs
def extract_ips(log_entries):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_addresses = []
    for entry in log_entries:
        match = re.search(ip_pattern, entry)
        if match:
            ip_addresses.append(match.group())
    return ip_addresses

# Function to detect brute-force login attempts
def detect_brute_force(log_entries, threshold=5, time_window=5):
    login_pattern = r'Failed password for .* from (\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'
    login_attempts = defaultdict(list)

    for entry in log_entries:
        match = re.search(login_pattern, entry)
        if match:
            ip = match.group(1)
            timestamp = extract_timestamp(entry)
            if timestamp:
                login_attempts[ip].append(timestamp)
    
    brute_force_ips = []
    for ip, timestamps in login_attempts.items():
        timestamps.sort()
        for i in range(len(timestamps) - threshold + 1):
            if (timestamps[i + threshold - 1] - timestamps[i]).total_seconds() / 60 <= time_window:
                brute_force_ips.append(ip)
                break

    return brute_force_ips

# Function to extract timestamp from log entries
def extract_timestamp(log_entry):
    # Adjust regex and date format as per your log format
    timestamp_pattern = r'\w{3} \d{1,2} \d{2}:\d{2}:\d{2}'
    match = re.search(timestamp_pattern, log_entry)
    if match:
        try:
            return datetime.datetime.strptime(match.group(), "%b %d %H:%M:%S")
        except ValueError:
            return None
    return None

# Main function to analyze logs
def analyze_logs(log_file):
    log_entries = parse_logs(log_file)
    print(f"Total log entries: {len(log_entries)}")

    # Extract IP addresses
    ip_addresses = extract_ips(log_entries)
    print(f"Unique IP addresses: {len(set(ip_addresses))}")

    # Detect brute-force attempts
    brute_force_ips = detect_brute_force(log_entries)
    if brute_force_ips:
        print("\nSuspicious IPs with potential brute-force attempts:")
        for ip in brute_force_ips:
            print(f"  - {ip}")
    else:
        print("\nNo brute-force attempts detected.")

# Example log file
if __name__ == "__main__":
    log_file = input("Enter the path to the log file (e.g., /var/log/auth.log): ")
    analyze_logs(log_file)
