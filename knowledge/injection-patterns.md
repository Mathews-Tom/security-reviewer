# Injection Patterns Reference

Detection patterns and remediation for injection vulnerabilities across languages.

## SQL Injection

### Vulnerable Patterns

| Language | Vulnerable Code | Detection Signal |
|----------|----------------|------------------|
| Python | `f"SELECT * FROM users WHERE id = {user_id}"` | f-string/format in SQL |
| Python | `cursor.execute("SELECT * FROM users WHERE id = " + user_id)` | String concat in execute() |
| Node.js | `` `SELECT * FROM users WHERE id = ${req.params.id}` `` | Template literal in query |
| Java | `"SELECT * FROM users WHERE id = " + request.getParameter("id")` | Concat in prepareStatement arg |
| Go | `fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)` | Sprintf in query string |

### Safe Patterns

| Language | Parameterized Query |
|----------|-------------------|
| Python | `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` |
| Node.js | `db.query("SELECT * FROM users WHERE id = $1", [userId])` |
| Java | `stmt.setString(1, userId)` with `?` placeholder |
| Go | `db.Query("SELECT * FROM users WHERE id = $1", id)` |

### Second-Order SQL Injection
- Data stored in DB without sanitization, later used in another query
- Detection: trace stored values to subsequent query construction

## Command Injection

### Vulnerable Functions

| Language | Dangerous Functions |
|----------|-------------------|
| Python | `os.system()`, `subprocess.run(shell=True)`, `os.popen()`, `eval()`, `exec()` |
| Node.js | `child_process.exec()`, `eval()`, `Function()`, `vm.runInContext()` |
| Ruby | `` `backticks` ``, `system()`, `exec()`, `%x{}`, `IO.popen()` |
| PHP | `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()` |
| Java | `Runtime.exec()`, `ProcessBuilder` with unsanitized args |

### Safe Alternatives

| Instead Of | Use |
|-----------|-----|
| `os.system(cmd)` | `subprocess.run(["cmd", "arg1"], shell=False)` |
| `child_process.exec(cmd)` | `child_process.execFile(bin, args)` |
| `eval(user_input)` | Structured parser (JSON.parse, ast.literal_eval) |

## NoSQL Injection

### MongoDB Operator Injection
```javascript
// Vulnerable: req.body passed directly to query
db.users.find({ username: req.body.username, password: req.body.password })
// Attack: { "password": { "$ne": "" } } bypasses auth
```

### Detection Signals
- User input directly in MongoDB query objects
- Missing schema validation on query parameters
- `$where`, `$gt`, `$ne`, `$regex` from user-controlled input

## Template Injection

### Server-Side Template Injection (SSTI)

| Engine | Test Payload | Vulnerable If |
|--------|-------------|---------------|
| Jinja2 | `{{7*7}}` | Returns `49` |
| Twig | `{{7*7}}` | Returns `49` |
| Freemarker | `${7*7}` | Returns `49` |
| Pebble | `{{7*7}}` | Returns `49` |

### Detection
- User input passed as template string (not template variable)
- `render_template_string(user_input)` in Flask
- Template compilation with user-supplied content

## LDAP Injection

### Special Characters
- `*`, `(`, `)`, `\`, NUL — must be escaped in DN components
- Detection: user input in LDAP filter without escaping
- Safe: use `ldap3.utils.dn.escape_rdn()` or equivalent
