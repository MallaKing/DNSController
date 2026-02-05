# Python DNS Sinkhole + SafeSearch Firewall (Windows)

A local DNS firewall and sinkhole controller built in Python that runs as a custom DNS resolver on Windows.  
It acts as a middle layer between client applications and upstream DNS servers and applies filtering, SafeSearch enforcement, caching, and domain blocking in real time.

---

## Features

- Local DNS resolver (UDP port 53)
- DNS sinkhole for blocked domains (returns 0.0.0.0)
- Global blocklist auto-download (StevenBlack hosts list)
- User blocklist + whitelist support
- Wildcard domain blocking
- SafeSearch enforcement at DNS level:
  - Google forced SafeSearch
  - Bing strict mode
  - YouTube restricted routing
- IPv4 + IPv6 handling (fast AAAA fallback logic)
- Multi-threaded query handling
- In-memory DNS caching with TTL
- Real-time Tkinter GUI:
  - Live DNS query logs
  - Right-click block / whitelist controls
  - SafeSearch toggle
  - Rule persistence
- Automatic Windows DNS routing to localhost using subprocess

---

## Windows-Specific Behavior (Important)

This tool is designed for Windows only.

On startup:
- Changes active network adapter DNS to 127.0.0.1 using `netsh`

On normal exit (closing Tkinter window):
- DNS settings are restored to DHCP automatically

If the program is forcefully terminated:
- DNS settings will NOT revert automatically
- You must manually reset:

netsh interface ip set dns name="YOUR_INTERFACE_NAME" dhcp
ipconfig /flushdns

---

## Manual Configuration Required

You must edit this constant in the code before running:

ACTIVE_INTERFACE = "Wi-Fi"

Adapter names differ across systems.

Find yours with:

netsh interface show interface

Then update the value in the script.

---

## Filtering Order

1. SafeSearch redirect rules
2. YouTube restricted routing rules
3. Whitelist override
4. User blocklist + wildcard rules
5. Global blocklist
6. Cache lookup
7. Upstream forward (8.8.8.8)

Blocked domains resolve to:

0.0.0.0

---

## Running

Run as Administrator:

python dns_firewall.py

Admin rights are required for:
- Binding to port 53
- Changing DNS adapter settings

---

## Dependencies

Python 3.9+
dnslib

Install:

pip install -r requirements.txt

---

## Tested On

Windows 10  
Windows 11

---

## Disclaimer

This program modifies system DNS settings while running.  
Use on personal systems only unless properly reviewed and hardened.

---

## License

MIT

