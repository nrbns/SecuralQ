# SecuraIQ local security tools

Built-in tools always work (no install). PATH tools light up when installed on the host running SecuraIQ.

## Built-in
ports, http, tls, dns, whois (RDAP), robots, tech, headers_security, cve_lookup

## PATH (optional)
nmap, nikto, nuclei, whatweb, dig, curl, sslscan, sslyze, gobuster, ffuf, traceroute/tracert, ping, openssl, wafw00f

## How to use
1. Enable **Security tools** in the sidebar (on by default)
2. Set **Target IP** to a lab/private host you own (or HTB/THM VPN IP)
3. Mode **Vuln Assessment** auto-runs the light tool set
4. Or instruct: `run nmap and http on 192.168.56.101`
5. Heavy tools (nuclei, nikto, ffuf, gobuster) run when you name them

## APIs
- `GET /api/tools` — availability
- `POST /api/tools/run` — `{ "target": "192.168.1.10", "tools": ["nmap","http"], "authorized_target": true }`
- `POST /api/tools/run/stream` — same body; NDJSON events (`start`, `tool_start`, `tool_done`, `done`) for realtime UI
- Auto chat tools use a light builtin set only (`dns`, `ports`, `http`, `headers_security`); heavy/PATH tools need an explicit ask

## Safety
Private/lab ranges by default. Public IPs require **I own / authorized this target**. No CIDR blasts. Argv allowlisted.
