# OWASP Top 10 (2021) Reference

Quick-reference taxonomy for mapping vulnerabilities to OWASP categories.

## Category Index

| ID | Category | CWE Coverage | Typical Severity |
|----|----------|-------------|------------------|
| A01 | Broken Access Control | CWE-200, CWE-284, CWE-285, CWE-352, CWE-639 | CRITICAL |
| A02 | Cryptographic Failures | CWE-259, CWE-261, CWE-327, CWE-328, CWE-330 | HIGH-CRITICAL |
| A03 | Injection | CWE-20, CWE-74, CWE-79, CWE-89, CWE-94 | CRITICAL |
| A04 | Insecure Design | CWE-209, CWE-256, CWE-501, CWE-522 | MEDIUM-HIGH |
| A05 | Security Misconfiguration | CWE-2, CWE-11, CWE-16, CWE-388 | MEDIUM-HIGH |
| A06 | Vulnerable Components | CWE-937, CWE-1035, CWE-1104 | HIGH |
| A07 | Auth Failures | CWE-255, CWE-287, CWE-384 | CRITICAL |
| A08 | Data Integrity Failures | CWE-345, CWE-502, CWE-829 | HIGH-CRITICAL |
| A09 | Logging Failures | CWE-117, CWE-223, CWE-532, CWE-778 | MEDIUM |
| A10 | SSRF | CWE-918 | HIGH-CRITICAL |

## Detection Signals by Category

### A01: Broken Access Control
- Missing authorization checks on endpoints
- IDOR: user-supplied ID used without ownership validation
- CORS misconfiguration allowing arbitrary origins
- Directory traversal via path manipulation
- Metadata manipulation (JWT, cookies, hidden fields)

### A02: Cryptographic Failures
- Plaintext transmission of sensitive data
- MD5 or SHA1 for password hashing
- Hardcoded encryption keys
- ECB mode usage
- Missing TLS enforcement

### A03: Injection
- String concatenation in SQL/NoSQL queries
- User input in OS commands (shell=True)
- Template injection via unescaped user content
- LDAP injection through unsanitized DN components
- XPath injection in XML queries

### A05: Security Misconfiguration
- Debug mode in production
- Default credentials unchanged
- Unnecessary features enabled
- Missing security headers
- Verbose error messages with stack traces

### A07: Authentication Failures
- Credential stuffing (no rate limiting)
- Weak password policies
- Session fixation
- Missing MFA on sensitive operations
- Predictable session tokens

### A08: Data Integrity Failures
- Insecure deserialization (pickle, YAML unsafe load)
- Missing integrity checks on CI/CD pipelines
- Unsigned software updates
- Prototype pollution in JavaScript

### A10: SSRF
- User-supplied URLs in server-side requests
- DNS rebinding bypasses
- Cloud metadata endpoint access (169.254.169.254)
- Redirect-following without destination validation

## Severity Mapping

| Exploitability | Impact | Resulting Severity |
|----------------|--------|--------------------|
| Easy (no auth required) | Data breach / RCE | CRITICAL |
| Easy | Limited data exposure | HIGH |
| Requires conditions | System compromise | HIGH |
| Requires conditions | Information disclosure | MEDIUM |
| Difficult | Minor impact | LOW |
