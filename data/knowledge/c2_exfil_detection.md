# Command-and-Control / Exfiltration Detection

## Common C2 patterns
- Regular beacon intervals to low-reputation hosts
- Small HTTP POSTs followed by larger staged uploads
- DNS tunneling or TXT-based command retrieval
- User-Agent strings inconsistent with the host role

## Exfiltration indicators
- Archive creation followed by outbound transfer
- Cloud storage access from servers that do not normally use it
- Sudden spike in egress to newly observed destinations
- Repeated HTTPS connections with low byte counts at fixed intervals

## Network hunting
- Netflow for periodic beacon timing
- Proxy logs for rare domains and categories
- DNS logs for long subdomains / high-entropy labels
- TLS metadata (JA3/JA4) for new fingerprints in the environment

## Detection examples
```spl
index=proxy
| stats count min(_time) as first max(_time) as last by src_ip, dest_domain, user_agent
| eval duration=last-first
| where count > 20 AND duration > 1800
```

```yaml
title: Suspicious Repeating DNS Queries
logsource:
  product: dns
detection:
  selection:
    QueryName|re: '^[A-Za-z0-9]{20,}\.'
  condition: selection
```

## Response
1. Contain affected host
2. Block domains/IPs at DNS, proxy, and firewall
3. Search fleet for same JA3, domain, or User-Agent
4. Review archives created before egress

## Prevention
- Egress filtering by role
- DNS security / sinkholing
- Proxy allow-lists for sensitive systems
- Alerting on new outbound destinations from servers
