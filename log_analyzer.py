from collections import Counter
import re

FAILED_LOGIN_PATTERN = r"Failed login from (\d+\.\d+\.\d+\.\d+)"

def analyze_log(file_path):
    ip_addresses = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                match = re.search(FAILED_LOGIN_PATTERN, line)
                if match:
                    ip_addresses.append(match.group(1))

        if not ip_addresses:
            print("No failed login attempts found.")
            return

        ip_counts = Counter(ip_addresses)

        print("\n--- Suspicious Login Activity Report ---")
        for ip, count in ip_counts.items():
            print(f"IP Address: {ip} | Failed Attempts: {count}")

            if count >= 5:
                print(f"⚠️ Possible brute-force attack detected from {ip}")

    except FileNotFoundError:
        print("Error: Log file not found.")
    except Exception as error:
        print(f"Unexpected error: {error}")

if __name__ == "__main__":
    log_file = input("Enter log file name: ")
    analyze_log(log_file)
