# Evilginx Local Lab (Training Only)

This reference is for **isolated local training**, demonstrations, and defensive understanding only. Do **not** expose the lab to the Internet or use it against real users, third-party services, or production credentials.

## Safe use cases
- Study reverse-proxy phishing mechanics in a containerized lab
- Test phishlet behavior against a fake MFA application you control
- Run blue-team demos for detection and response training

## Local-lab constraints
- Use host-only or NAT networking
- Do not route traffic to public domains
- Use self-signed certificates in a lab only
- Use fake credentials and fake OTPs only
- Destroy containers and snapshots after exercises

## Example lab architecture
```text
[Host machine]
  |-- targetsite.local      -> fake local training app
  |-- targetsile.local      -> typo-squatted local lab domain
  `-- Docker network only, not Internet-exposed
```

## Defensive learning goals
1. Understand how reverse-proxy phishing captures session tokens
2. Observe HTTP headers, cookies, and MFA flow behavior
3. Build detections for suspicious proxying, cloned login pages, and token replay

## Detection ideas
- Monitor for lookalike domains and typosquatting in DNS/proxy logs
- Alert on new TLS certs for internal-only lookalike hostnames
- Detect impossible-travel or unusual session replay after MFA
- Hunt for mismatched user-agent / IP patterns between login and session use

## Blue-team follow-up
- Enforce phishing-resistant MFA (FIDO2/WebAuthn)
- Use conditional access and device binding where possible
- Shorten token lifetime and monitor for replay anomalies
- Train users with clearly isolated phishing simulations only

## Lab reference
The `zinzloun/Evilginx_Lab` repository describes a Docker-based local training environment for phishlet testing and demos. Treat it as a **lab-only reference** and keep it isolated from public networks.
