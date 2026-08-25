# Pentest Tool Cheatsheet (Authorized Scope)

## nmap
```bash
nmap -sC -sV -oA out <target>
nmap -p- --min-rate 1000 <target>
nmap --script vuln <target>          # lab only
nmap -sU --top-ports 20 <target>
```

## ffuf / gobuster
```bash
ffuf -u http://target/FUZZ -w wordlist.txt -fc 404
ffuf -u http://target/FUZZ -w wordlist.txt -H "Host: FUZZ.target.com"
gobuster dir -u http://target -w common.txt -t 40
gobuster vhost -u http://target -w subdomains.txt
```

## sqlmap (scoped targets only)
```bash
sqlmap -u "http://lab/page?id=1" --batch --risk=1 --level=1
sqlmap -r request.txt -p id --batch
sqlmap -u URL --dbs --batch
```

## Burp Suite
- Proxy: 127.0.0.1:8080
- Export request → sqlmap with `-r`
- Scanner: active scan only in-scope lab apps

## hydra (lab creds only)
```bash
hydra -l admin -P rockyou.txt ssh://<lab_ip>
hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"
```

## john / hashcat
```bash
john --wordlist=rockyou.txt hashes.txt
hashcat -m 1000 hashes.txt rockyou.txt    # NTLM
hashcat -m 3200 hashes.txt rockyou.txt    # bcrypt
```

## impacket (lab AD)
```bash
secretsdump.py domain/user:pass@<dc_ip>
psexec.py domain/user:pass@<target>
GetNPUsers.py domain/ -usersfile users.txt -dc-ip <dc_ip>
```

## wireshark / tcpdump
```bash
tcpdump -i eth0 port 80 -w capture.pcap
tshark -r capture.pcap -Y "http.request"
```

## nuclei (scoped)
```bash
nuclei -u http://target -t cves/
nuclei -l urls.txt -severity critical,high
```

## General rules
- Always confirm written authorization
- Use `--batch` and rate limits on automated tools
- Log commands and findings for reports
