# Stealer / Clipper Detection

## Stealer behaviors
- Reads browser profile paths and credential databases
- Extracts cookies, saved passwords, autofill, and tokens
- Searches common wallet or application config directories
- Archives data to temporary folders before upload

## Clipper behaviors
- Watches clipboard contents continuously
- Replaces cryptocurrency wallet addresses with attacker-controlled values
- Often runs from user startup folders or scheduled tasks

## Windows log / telemetry ideas
- Sysmon Event ID 1: suspicious child processes under browsers
- Sysmon Event ID 11: file creation in temp/archive paths
- Sysmon Event ID 13: registry Run key persistence
- Sysmon Event ID 3: outbound connections to rare domains shortly after browser access

## Hunt examples
1. Browser data access followed by archive creation
2. Clipboard API abuse combined with persistence
3. `sqlite` access to browser stores from non-browser processes
4. Network egress shortly after reading `%LocalAppData%` browser paths

## Sigma-style ideas
```yaml
title: Non-Browser Process Accesses Browser Credential Paths
logsource:
  product: windows
  category: file_access
detection:
  selection:
    TargetFilename|contains:
      - '\AppData\Local\Google\Chrome\User Data\'
      - '\AppData\Roaming\Mozilla\Firefox\Profiles\'
  filter_main:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
  condition: selection and not filter_main
```

## Response
- Isolate host immediately
- Revoke browser sessions and rotate exposed credentials
- Reset wallet or exchange access if clipboard hijack suspected
- Preserve archive files, memory, and outbound connection logs

## Prevention
- Browser hardening and enterprise password managers
- EDR rules for browser profile access
- Restrict unsigned scripts and user-writable autoruns
- User awareness for wallet address verification
