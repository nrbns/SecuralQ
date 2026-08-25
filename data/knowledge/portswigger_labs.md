# PortSwigger Web Security Academy — Lab Patterns

## Access
Free labs at portswigger.net/web-security — use Burp Suite Community or Pro.

## SQL injection labs
1. **String quotes** — break out with `'`
2. **Boolean** — `' AND '1'='1` vs `' AND '1'='2`
3. **UNION** — match column count: `' ORDER BY 1--`, `' ORDER BY 2--` ...
4. **Blind** — conditional responses or time delays

Example UNION extraction (MySQL):
```sql
' UNION SELECT username, password FROM users--
```

## XSS labs
| Context | Approach |
|---------|----------|
| HTML body | `<script>alert(1)</script>` |
| Attribute | `" onmouseover="alert(1)` |
| JS string | `';alert(1)//` |
| DOM | Trace source → sink in DevTools |

## CSRF labs
- Check if CSRF token is validated
- Test token removal, fixed token, token in cookie only
- Craft HTML form on attacker server (lab-provided exploit server)

## SSRF labs
```
http://localhost/admin
http://169.254.169.254/   (cloud metadata — lab only)
```

## Authentication labs
- Username enumeration via response differences
- Brute force with rate limit bypass (IP rotation in lab)
- Password reset token predictability

## Access control labs
- Change user ID in URL/API: `/api/orders/123` → `/api/orders/124`
- Test horizontal and vertical privilege escalation

## File upload labs
- Bypass extension filters: `shell.php.jpg`, double extensions
- Content-Type manipulation
- Polyglot files (lab context)

## Burp workflow
1. Proxy → intercept request
2. Send to Repeater for manual tests
3. Intruder for fuzzing (authorized lab only)
4. Collaborator for out-of-band detection
