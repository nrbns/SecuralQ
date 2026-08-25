# High-Impact CVE Summaries (Defensive + Lab Awareness)

## Log4Shell — CVE-2021-44228
**Component:** Apache Log4j 2.x  
**Impact:** Unauthenticated RCE via JNDI lookup in logged strings  
**Detection:** `${jndi:ldap://` in headers, User-Agent, form fields  
**Mitigation:** Upgrade Log4j ≥ 2.17.1, remove JndiLookup class, WAF rules  
**Lab:** Dedicated HTB/THM rooms — never probe random internet hosts

## ProxyLogon — CVE-2021-26855 (Exchange)
**Impact:** SSRF leading to unauthenticated access in on-prem Exchange  
**Mitigation:** Apply Microsoft patches, restrict external access  
**Note:** Historical — patch verification only in authorized assessments

## EternalBlue — MS17-010
**Impact:** SMB RCE on unpatched Windows (SMBv1)  
**Detection:** `nmap --script smb-vuln-ms17-010`  
**Mitigation:** Disable SMBv1, install MS17-010 patch  
**Lab:** Metasploitable / legacy Windows VMs only

## Shellshock — CVE-2014-6271
**Impact:** Bash env variable RCE via CGI scripts  
**Test (lab):** `() { :; }; echo vulnerable` in User-Agent  
**Mitigation:** Patch bash, avoid CGI with env vars

## Spring4Shell — CVE-2022-22965
**Impact:** RCE in Spring MVC with specific JDK/Tomcat configs  
**Mitigation:** Spring Framework 5.3.18+, 5.2.20+  
**Detection:** Class loader manipulation attempts in POST params

## MOVEit — CVE-2023-34362
**Impact:** SQL injection → RCE in MOVEit Transfer  
**Mitigation:** Vendor patches, isolate file transfer systems

## Citrix Bleed — CVE-2023-4966
**Impact:** Session token leak in Citrix NetScaler  
**Mitigation:** Patch immediately, reset sessions

## Assessment approach
1. Inventory software versions (nmap -sV, nuclei, manual)
2. Cross-reference NVD / vendor advisories
3. Validate only in scope with proof-of-concept in lab first
4. Report with CVSS, affected assets, remediation steps
