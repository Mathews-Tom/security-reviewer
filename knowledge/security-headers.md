# Security Headers Reference

Required HTTP security headers, correct values, and misconfiguration detection.

## Required Headers

| Header | Required Value | Purpose |
|--------|---------------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Force HTTPS |
| `Content-Security-Policy` | See CSP section | Prevent XSS, data injection |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Prevent clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restrict browser features |
| `Cache-Control` | `no-store` (authenticated responses) | Prevent cache leakage |

## Headers to Remove

| Header | Reason |
|--------|--------|
| `X-Powered-By` | Reveals technology stack |
| `Server` (version) | Reveals server software version |
| `X-AspNet-Version` | Reveals .NET version |
| `X-AspNetMvc-Version` | Reveals MVC version |

## HSTS Configuration

### Minimum Requirements
- `max-age` >= 31536000 (1 year)
- `includeSubDomains` present
- Set on all HTTPS responses

### Common Misconfigurations
| Issue | Severity |
|-------|----------|
| `max-age=0` | HIGH — disables HSTS |
| Missing `includeSubDomains` | MEDIUM — subdomains unprotected |
| Set over HTTP | HIGH — header ignored, attackable |
| Short max-age (< 1 year) | LOW — reduces protection window |

## Content Security Policy (CSP)

### Recommended Baseline
```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
object-src 'none';
```

### Dangerous Directives

| Directive | Risk | Severity |
|-----------|------|----------|
| `script-src 'unsafe-inline'` | Allows inline scripts, negates XSS protection | HIGH |
| `script-src 'unsafe-eval'` | Allows eval(), Function(), setTimeout(string) | HIGH |
| `default-src *` | Allows loading from any source | HIGH |
| `script-src *` | Allows scripts from any domain | CRITICAL |
| Missing `object-src` | Falls back to default-src, may allow Flash/plugins | MEDIUM |
| Missing `base-uri` | Base tag injection can redirect relative URLs | MEDIUM |

### CSP Reporting
```
Content-Security-Policy-Report-Only: <policy>; report-uri /csp-report
```

## CORS Configuration

### Secure Configuration
```
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 600
Vary: Origin
```

### Dangerous Patterns

| Pattern | Severity | Issue |
|---------|----------|-------|
| `Allow-Origin: *` with credentials | CRITICAL | Wildcard + credentials = any site reads response |
| Reflecting `Origin` header without allowlist | HIGH | Bypasses CORS entirely |
| `Allow-Origin: null` | HIGH | Sandboxed iframes and data: URIs send null origin |
| Missing `Vary: Origin` | MEDIUM | Cache poisoning across origins |
| Overly broad origin regex | MEDIUM | Subdomain takeover risk |

### Detection Signals
- `Access-Control-Allow-Origin` set to `*` on authenticated endpoints
- Origin header reflected directly without validation
- Missing `Vary: Origin` when ACAO changes per request
- Credentials mode with wildcard origin

## Cookie Security Flags

| Flag | Value | Detection Signal When Missing |
|------|-------|------------------------------|
| `Secure` | Required | Cookie transmitted over HTTP |
| `HttpOnly` | Required for session | JavaScript can access cookie |
| `SameSite` | `Strict` or `Lax` | CSRF via cross-site requests |
| `Path` | Restrictive | Cookie sent to unrelated paths |
| `__Host-` prefix | Recommended | Ensures Secure + no Domain + Path=/ |
