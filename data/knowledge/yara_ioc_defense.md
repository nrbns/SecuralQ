# YARA Rules & IOC Handling (Defensive)

## YARA rule structure
```yara
rule Example_Malware_Family {
    meta:
        author = "SOC Team"
        description = "Detects example family strings"
        severity = "high"
        mitre_attack = "T1059.001"
    strings:
        $s1 = "cmd.exe /c" ascii wide
        $s2 = { 4D 5A 90 00 }   // MZ header
        $s3 = /https?:\/\/[a-z0-9.-]+\/(payload|update)/ 
    condition:
        $s2 at 0 and 1 of ($s1, $s3)
}
```

## Testing rules
```bash
yara -s rule.yar /path/to/samples/
yarGen -m sample_dir/     # generate from known-malware corpus (lab)
```

## IOC formats

### STIX 2.1 indicator (simplified)
```json
{
  "type": "indicator",
  "pattern": "[domain-name:value = 'evil-c2.example.com']",
  "valid_from": "2026-01-01T00:00:00Z",
  "labels": ["malicious-activity"]
}
```

### MISP event attributes
- ip-src, ip-dst, domain, url, md5, sha256, mutex, regkey

## IOC lifecycle
1. **Collect** from sandbox/IR
2. **Validate** — false positive check against known-good
3. **Enrich** — VT, passive DNS, WHOIS
4. **Deploy** — firewall, proxy, EDR custom IOC, DNS block
5. **Expire** — C2 rotates; review IOCs after 30-90 days

## Blocking (defensive)
```
# Palo Alto custom URL category
# Pi-hole / DNS sinkhole
# Windows Defender ASR / custom indicators
# Suricata rule:
alert dns $HOME_NET any -> any any (msg:"MALWARE C2 DNS"; dns.query; content:"bad.domain.com"; nocase; sid:1000001;)
```

## Sigma for host IOCs
```yaml
title: Suspicious Scheduled Task Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
    TaskContent|contains:
      - '\AppData\Roaming\'
      - 'powershell'
  condition: selection
```

## Threat intel feeds (legitimate)
- CISA AIS, AlienVault OTX, abuse.ch (URLhaus, Feodo)
- Vendor advisories (Microsoft, CrowdStrike public reports)

Use feeds to tune detections — never to operationalize attacks.
