# Sigma Rules Library (Defensive)

## Process creation — suspicious PowerShell
```yaml
title: PowerShell Encoded Command
id: ps-encoded-001
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - 'FromBase64String'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

## Registry — run key persistence
```yaml
title: Run Key Modification
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run'
    Image|endswith:
      - '\reg.exe'
      - '\powershell.exe'
      - '\cmd.exe'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

## Network — suspicious outbound port
```yaml
title: Outbound Connection to Suspicious Port
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
      - 1337
    Initiated: 'true'
  condition: selection
level: medium
tags:
  - attack.command_and_control
```

## Linux — reverse shell bash
```yaml
title: Bash Reverse Shell Pattern
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/bash'
    CommandLine|contains:
      - '/dev/tcp/'
      - '0>&1'
  condition: selection
level: high
```

## Deployment
1. Install Sigma CLI: `pip install sigma-cli`
2. Convert: `sigma convert -t splunk rule.yml`
3. Test in lab with atomic red team
4. Tune false positives before production
