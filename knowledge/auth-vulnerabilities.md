# Authentication & Authorization Vulnerabilities Reference

Detection patterns for broken auth, session management, and access control flaws.

## Password Storage

### Insecure Hashing Detection

| Algorithm | Status | Detection Signal |
|-----------|--------|-----------------|
| MD5 | CRITICAL | `hashlib.md5()`, `MD5.Create()`, `md5()` |
| SHA1 | CRITICAL | `hashlib.sha1()`, `SHA1.Create()`, `sha1()` |
| SHA256 (bare) | HIGH | No salt, no iteration — too fast for passwords |
| bcrypt | SAFE | `bcrypt.hash()`, `password_hash(PASSWORD_BCRYPT)` |
| scrypt | SAFE | `hashlib.scrypt()`, `crypto.scrypt()` |
| argon2id | SAFE | `argon2.hash()`, `PasswordHasher()` |

### Detection Signals
- Password variable assigned to hash function without salt
- Custom password hashing (not using established library)
- Comparison with `==` instead of constant-time comparison

## JWT Vulnerabilities

### Common Misconfigurations

| Issue | Severity | Detection Signal |
|-------|----------|-----------------|
| `alg: "none"` accepted | CRITICAL | Missing algorithm validation in verify |
| HS256 with weak secret | HIGH | Short or common secret string |
| Missing `exp` validation | HIGH | No expiry check in verification |
| Secret in source code | CRITICAL | JWT secret as string literal |
| Missing `iss`/`aud` check | MEDIUM | No issuer/audience validation |
| Symmetric signing (HS256) | MEDIUM | Shared secret between services |

### Vulnerable Code Patterns
```python
# CRITICAL: no algorithm restriction
jwt.decode(token, secret)

# SAFE: algorithm explicitly specified
jwt.decode(token, secret, algorithms=["RS256"])
```

```javascript
// CRITICAL: no algorithm verification
jwt.verify(token, secret)

// SAFE: explicit algorithm
jwt.verify(token, secret, { algorithms: ["RS256"] })
```

## Session Management

### Session Fixation
- Detection: session ID not regenerated after authentication
- Check: `request.session.regenerate()` / `session_regenerate_id()` after login

### Session Configuration Flags

| Flag | Required Value | Risk If Missing |
|------|---------------|-----------------|
| `HttpOnly` | true | XSS can steal session cookie |
| `Secure` | true | Cookie sent over HTTP (interceptable) |
| `SameSite` | Strict or Lax | CSRF vulnerability |
| `Max-Age` / `Expires` | Set | Indefinite session lifetime |
| `Path` | Restrictive | Cookie sent to unrelated paths |

## Access Control (Authorization)

### IDOR Detection
```python
# VULNERABLE: no ownership check
@app.get("/api/orders/{order_id}")
def get_order(order_id: int):
    return db.query(Order).get(order_id)

# SAFE: ownership validation
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, user: User = Depends(get_current_user)):
    order = db.query(Order).get(order_id)
    if order.user_id != user.id:
        raise HTTPException(403)
    return order
```

### Missing Auth Check Signals
- Route handler without auth decorator/middleware
- Admin endpoints without role verification
- API endpoints accessible without Bearer token
- File download endpoints without access control

## Rate Limiting

### Required Endpoints

| Endpoint Type | Recommended Limit |
|--------------|-------------------|
| Login | 5/min per account, 20/min per IP |
| Password reset | 3/min per account |
| Registration | 10/min per IP |
| API (authenticated) | 100/min per user |
| API (unauthenticated) | 20/min per IP |

### Detection Signals
- Login endpoint without rate limiting middleware
- Missing `429 Too Many Requests` response handling
- No brute-force protection library (express-rate-limit, django-ratelimit)

## MFA Bypass Patterns
- MFA check only on login, not on sensitive operations
- MFA code accepted without expiry
- MFA bypass via API endpoint that skips web flow
- Recovery codes stored in plaintext
