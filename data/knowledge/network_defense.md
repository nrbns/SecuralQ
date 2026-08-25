# Network Defense & Monitoring

## Segmentation
- DMZ for public-facing services
- Separate VLAN for servers, workstations, IoT
- Firewall rules: default deny, explicit allow
- Jump hosts for admin access

## IDS/IPS placement
- Perimeter: north-south traffic
- Core switches: east-west (microsegmentation)
- Tune signatures to reduce noise

## Suricata example — alert on exploit attempt
```
alert http any any -> any any (msg:"ET WEB_SERVER SQL Injection"; \
  flow:established,to_server; content:"UNION"; nocase; \
  content:"SELECT"; nocase; sid:9000001; rev:1;)
```

## Netflow analysis
Hunt for:
- Beaconing (regular interval connections)
- Large data transfers to rare destinations
- Internal hosts scanning /24 subnets

## Firewall log review
```bash
# Parse denied connections (lab SIEM export)
grep "DENY" fw.log | awk '{print $3}' | sort | uniq -c | sort -rn
```

## Hardening
- Disable unused services
- VPN + MFA for remote access
- WPA3-Enterprise for wireless
- 802.1X port authentication

## DDoS mitigation
- Rate limiting at edge
- CDN for public web
- Anycast scrubbing for volumetric attacks

## PCAP analysis (Wireshark filters)
```
http.request.method == "POST"
tls.handshake.type == 1
dns.qry.name contains "suspicious"
ip.addr == 10.0.0.50
```

## Zero Trust principles
- Verify explicitly
- Least privilege access
- Assume breach — log everything
