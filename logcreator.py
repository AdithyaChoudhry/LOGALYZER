import random
import time

# File path for the generated log file
output_log_file = "Sample.log"

# Sample data for generating logs
ip_addresses = [f"192.168.1.{i}" for i in range(1, 101)] + [f"203.0.113.{i}" for i in range(1, 11)] + [f"10.0.0.{i}" for i in range(1, 11)]
endpoints = ["/home", "/login", "/about", "/contact", "/dashboard", "/register", "/profile", "/feedback"]
status_codes = ["200", "401"]
methods = ["GET", "POST"]
error_messages = ["Invalid credentials", ""]
responses = range(128, 1025, 64)

# Function to generate a random log entry
def generate_log_entry():
    ip = random.choice(ip_addresses)
    timestamp = time.strftime("[%d/%b/%Y:%H:%M:%S +0000]", time.gmtime())
    method = random.choice(methods)
    endpoint = random.choice(endpoints)
    status = random.choice(status_codes)
    response_size = random.choice(responses)
    extra_info = random.choice(error_messages) if status == "401" else ""
    return f'{ip} - - {timestamp} "{method} {endpoint} HTTP/1.1" {status} {response_size} "{extra_info}"'

# Generate a log file
def generate_log_file(file_path, num_entries=100):
    with open(file_path, "w") as log_file:
        for _ in range(num_entries):
            log_file.write(generate_log_entry() + "\n")
    print(f"Generated log file with {num_entries} entries at {file_path}")

# Generate the file
generate_log_file(output_log_file, num_entries=1000)  # Change `num_entries` to increase/decrease the number of logs
