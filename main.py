import re
import csv
from collections import defaultdict

# Constants
LOG_FILE = r"C:\Users\choud\PycharmProjects\pythonProject7\Sample.log"
OUTPUT_CSV = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10  # Threshold for failed login attempts to flag as suspicious

def parse_log_file(log_file):
    # Initialize dictionaries to store data
    ip_requests = defaultdict(int)  # Counts the number of requests per IP
    endpoint_access = defaultdict(int)  # Tracks how many times each endpoint is accessed
    failed_logins = defaultdict(int)  # Keeps track of failed login attempts by IP

    with open(log_file, 'r') as file:
        # Go through each line in the log file
        for line in file:
            # Regex pattern to extract IP, endpoint, status code, and error message if any
            match = re.match(r'(\S+) - - \[.*\] "(?:GET|POST) (\S+) HTTP.*" (\d+)(?: .*"(Invalid credentials)")?', line)
            if match:
                # Extracted parts from the log line
                ip_address, endpoint, status_code, error_message = match.groups()[:4]

                # Track the number of requests per IP and the number of accesses per endpoint
                ip_requests[ip_address] += 1
                endpoint_access[endpoint] += 1

                # Check if the status code indicates a failed login (401) or if the message contains 'Invalid credentials'
                if status_code == '401' or (error_message and "Invalid credentials" in error_message):
                    failed_logins[ip_address] += 1

    return ip_requests, endpoint_access, failed_logins

def analyze_logs():
    # Parse the log file and collect data
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)

    # Sort IP requests to get the most frequent ones first
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

    # Find the most accessed endpoint (with the highest count)
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1], default=(None, 0))

    # Identify IPs with failed login attempts exceeding the threshold
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    return sorted_ip_requests, most_accessed_endpoint, suspicious_activity

def save_results_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activity):
    # Open a CSV file to save the results
    with open(OUTPUT_CSV, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write the IP address and request count data to the CSV
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted_ip_requests:
            writer.writerow([ip, count])

        # Write details of the most accessed endpoint
        writer.writerow([])  # Add an empty row for separation
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious activity details (failed login attempts)
        writer.writerow([])  # Add an empty row for separation
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def display_results(sorted_ip_requests, most_accessed_endpoint, suspicious_activity):
    # Display the results on the console
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Display suspicious activity if any is found
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo suspicious activity detected.")  # No suspicious activity found

def main():
    # Analyze the logs, display the results, and save them to CSV
    sorted_ip_requests, most_accessed_endpoint, suspicious_activity = analyze_logs()
    display_results(sorted_ip_requests, most_accessed_endpoint, suspicious_activity)
    save_results_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activity)

if __name__ == "__main__":
    main()
