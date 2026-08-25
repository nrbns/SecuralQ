# Burp Suite Workflows

## Setup
1. Configure browser proxy: 127.0.0.1:8080
2. Install Burp CA cert for HTTPS interception
3. Scope: Target → Scope → add lab URLs only

## Repeater workflow
1. Intercept request in Proxy
2. Send to Repeater (Ctrl+R)
3. Modify params, headers, cookies
4. Compare response length/status/content

## Intruder (lab fuzzing)
```
Positions: mark §param§
Attack type: Sniper (one param) or Cluster bomb (multiple)
Payloads: wordlist, numbers, null payloads
Grep - Match: error strings, "welcome", status 200
```

## Active scanner
- Enable only for in-scope lab applications
- Review false positives manually
- Export issues for report

## Extensions (useful)
- Autorize — IDOR testing (compare responses across users)
- JWT Editor — alg:none, key confusion in CTF
- Param Miner — hidden parameters
- Turbo Intruder — rate-limited fuzzing

## Common tests via Burp
| Vuln | Test |
|------|------|
| SQLi | `'`, `"`, `') OR ('1'='1` in each param |
| XSS | `<script>alert(1)</script>` in reflected fields |
| SSRF | `url=http://127.0.0.1`, collaborator URL |
| IDOR | Change numeric IDs, UUIDs across sessions |
| Auth bypass | Remove cookies, swap JWT, test HTTP methods |

## Collaborator
- Generate unique subdomain for blind SSRF/XXE
- Insert in payloads: `http://<collab>.oastify.com`
- Poll for DNS/HTTP callbacks
