# XSS Testing Methodology (Authorized Labs Only)

## Types
- **Reflected XSS**: payload in request echoed immediately in response.
- **Stored XSS**: payload persisted (comments, profiles) affecting other users.
- **DOM XSS**: sink in client-side JS without server round-trip.

## Lab testing steps
1. Identify reflection points: search boxes, error messages, URL params.
2. Inject benign probe: `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`.
3. Check encoding: HTML entity, attribute, JS context — each needs different payload.
4. Use PortSwigger XSS labs or DVWA security levels for practice.

## Common payloads (educational)
```html
<script>alert(document.domain)</script>
"><svg onload=alert(1)>
javascript:alert(1)
```

## Mitigations
- Context-aware output encoding (OWASP XSS Prevention Cheat Sheet)
- Content-Security-Policy (CSP)
- HttpOnly + Secure + SameSite cookies
- Input validation as defense-in-depth (not sole fix)

## Tools
- Burp Suite Repeater/Intruder
- SecuraIQ Web Scanner (built-in DAST, scoped)
- Browser DevTools for DOM inspection
