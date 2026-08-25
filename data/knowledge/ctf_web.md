# CTF Web Challenge Patterns

## Recon
- View source, robots.txt, sitemap.xml
- Check HTTP headers, cookies, hidden form fields
- Directory brute: ffuf, gobuster, feroxbuster

## Common web CTF tricks
- Base64/hex/rot13 encoded flags in comments
- JWT alg:none or weak HMAC secrets
- SSTI in template engines: `{{7*7}}`, `${7*7}`
- LFI: `?file=../../../etc/passwd`
- Command injection in ping/traceroute features

## Useful commands
```bash
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt
curl -s http://target/ | grep -i flag
echo "admin" | base64
```

## Flag format
Often `flag{...}`, `CTF{...}`, or HTB{...} — always read challenge description.

## Mindset
1. Enumerate everything
2. Fuzz parameters
3. Chain low-severity bugs into impact
4. Document findings as you go
