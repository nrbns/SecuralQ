# Burp Suite, Acunetix, Greenbone / OpenVAS (authorized)

Use these against **lab / staging / written-scope** targets only.

## Burp Suite
1. Set proxy `127.0.0.1:8080`, install CA in browser/lab VM
2. Add target to **Scope**
3. Manual: Proxy → Repeater → Intruder (lab apps: DVWA, Juice Shop, PortSwigger Academy)
4. Pro: Scanner on in-scope hosts only; export HTML/XML for remediation owners
5. FOSS twin: **SecuraIQ Web Scanner** (built-in DAST in SecuraIQ — no install) or optional ZAP export import

## Acunetix (licensed DAST)
1. Create scan for staging URL + auth
2. Exclude production/out-of-scope paths
3. Triage Critical/High → ticket with CVSS + owner
4. Without license: SecuraIQ Web Scanner + Nuclei + manual Burp

## Greenbone Vulnerability Manager (OpenVAS)
1. Install Greenbone Community Edition
2. Sync NVT feeds
3. Target = RFC1918 / VPN lab range (single hosts or small authorized sets)
4. Full + deep scan schedules; export PDF for CISO reporting
5. CLI: `gvm-cli` / GVM scripts when on PATH — SecuraIQ detects `openvas` / `gvm-cli`

## SecuraIQ usage
- Mode **Vuln Assessment** + Target IP → live probes
- Instruct: `run suite_guide` or `run zap and nmap on 192.168.56.101`
- Mode **CISO** → risk, ISO/NIST mapping, 30/60/90 roadmap from findings
