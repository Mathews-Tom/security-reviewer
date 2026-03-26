# XSS Patterns Reference

Detection patterns for reflected, stored, and DOM-based cross-site scripting.

## XSS Types

| Type | Data Flow | Persistence | Typical Severity |
|------|-----------|-------------|------------------|
| Reflected | Request → Response | None | MEDIUM-HIGH |
| Stored | Request → Database → Response | Persistent | HIGH-CRITICAL |
| DOM-based | Client-side source → Client-side sink | None | MEDIUM-HIGH |

## Reflected XSS Detection

### Vulnerable Patterns

| Framework | Vulnerable Code |
|-----------|----------------|
| Flask | `return f"<p>Hello {request.args['name']}</p>"` |
| Express | `res.send("<p>Hello " + req.query.name + "</p>")` |
| Django | `HttpResponse(f"<p>{request.GET['q']}</p>")` |
| PHP | `echo "<p>" . $_GET['name'] . "</p>";` |
| Spring | `model.addAttribute("name", request.getParameter("name"))` with `th:utext` |

### Sources (User Input Entry Points)
- `request.args`, `request.form`, `request.headers` (Flask)
- `req.query`, `req.params`, `req.body`, `req.headers` (Express)
- `request.GET`, `request.POST` (Django)
- `$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER` (PHP)
- URL fragments, `document.location`, `document.referrer` (DOM)

## Stored XSS Detection

### High-Risk Content Types
- User comments and messages
- Profile fields (display name, bio, website)
- Rich text / markdown editors
- File metadata (uploaded file names displayed)
- Forum posts, wiki pages

### Detection Signals
- Database content rendered in HTML without encoding
- User-generated content displayed via `innerHTML` or `{!! !!}` (Blade)
- Missing output encoding on retrieved database values

## DOM XSS Detection

### Dangerous Sinks

| Sink | Risk Level |
|------|------------|
| `element.innerHTML` | HIGH |
| `element.outerHTML` | HIGH |
| `document.write()` | HIGH |
| `document.writeln()` | HIGH |
| `eval()` | CRITICAL |
| `setTimeout(string)` | HIGH |
| `setInterval(string)` | HIGH |
| `new Function(string)` | CRITICAL |
| `element.insertAdjacentHTML()` | HIGH |
| `$.html()` (jQuery) | HIGH |

### Dangerous Sources

| Source | Risk |
|--------|------|
| `location.hash` | HIGH |
| `location.search` | HIGH |
| `location.href` | HIGH |
| `document.referrer` | MEDIUM |
| `document.cookie` | MEDIUM |
| `window.name` | MEDIUM |
| `postMessage` data | HIGH |

### React-Specific
- `dangerouslySetInnerHTML` — flag when value derives from user input or database
- JSX auto-escapes by default — safe for string interpolation
- `href={userInput}` — vulnerable to `javascript:` protocol

## Framework Protections

| Framework | Default Protection | Bypass Mechanism |
|-----------|-------------------|-----------------|
| React | JSX auto-escapes | `dangerouslySetInnerHTML`, `href` with javascript: |
| Angular | Template auto-escapes | `bypassSecurityTrustHtml()`, `[innerHTML]` |
| Vue | `{{ }}` auto-escapes | `v-html` directive |
| Django | Template auto-escapes | `|safe` filter, `{% autoescape off %}`, `mark_safe()` |
| Jinja2 | Auto-escape (if enabled) | `|safe` filter, `Markup()`, autoescape disabled |
| EJS | `<%= %>` escapes | `<%- %>` unescaped output |
| Handlebars | `{{ }}` escapes | `{{{ }}}` triple-stache unescaped |

## CSP as Defense Layer

### Effective CSP Directives
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'
```

### CSP Bypass Signals
- `script-src 'unsafe-inline'` — negates XSS protection
- `script-src 'unsafe-eval'` — allows eval-based XSS
- Overly broad allowlists (CDN domains hosting user content)
- Missing `object-src` directive
