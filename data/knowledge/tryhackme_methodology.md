# TryHackMe Methodology (Authorized Platform)

## Getting started
1. Deploy room machine via THM browser UI or AttackBox
2. Note target IP from room page (often `10.10.x.x`)
3. Use THM VPN or AttackBox — never scan outside room scope

## Recon workflow
```bash
nmap -sV -sC <machine_ip>
nmap -p- <machine_ip>   # if initial scan shows filtered ports
```

## Common room types

### Web exploitation
- View source, check comments and JS files
- `gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt`
- Test login forms for SQLi, default creds in room hints

### Privilege escalation rooms
- Linux: `sudo -l`, SUID binaries, cron jobs, kernel exploits (match room era)
- Windows: unquoted service paths, AlwaysInstallElevated, token impersonation

### Network rooms
- Wireshark PCAP analysis
- ARP spoofing only in isolated THM networks

## Useful THM tools (AttackBox pre-installed)
- `nmap`, `gobuster`, `burpsuite`, `john`, `hashcat`, `metasploit`

## Answer submission
- Flags often in `THM{...}` format
- Read task questions carefully — some need specific tool output

## Practice path
1. Complete "Jr Penetration Tester" path
2. OWASP Top 10 room
3. Pick offensive rooms matching your weak areas
