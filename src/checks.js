'use strict';

const SEV = {
  high:   'high',
  medium: 'medium',
  low:    'low',
  info:   'info',
};

const SEVERITY_ORDER = { high: 3, medium: 2, low: 1, info: 0 };

const REMEDIATION = {
  TOKEN_IN_URL: {
    summary: 'Move sensitive values out of URLs. Pass API keys and tokens in the Authorization or X-API-Key request header instead.',
    detail: `<p>URLs are logged by web servers, CDNs, proxies, and appear in browser history. Any sensitive value in a URL is at risk of exposure.</p>
<p><strong>Instead of:</strong></p>
<pre>GET /api/data?api_key=sk-prod-abc123</pre>
<p><strong>Use a request header:</strong></p>
<pre>GET /api/data
Authorization: Bearer sk-prod-abc123
// or
X-API-Key: sk-prod-abc123</pre>
<p><strong>In Express.js:</strong></p>
<pre>// Read from header, not query param
const apiKey = req.headers['x-api-key'];
if (!apiKey || apiKey !== process.env.API_KEY) {
  return res.status(401).json({ error: 'Unauthorized' });
}</pre>
<p><strong>Verification:</strong> Re-export the HAR after the fix and rerun this scan. The finding should no longer appear.</p>`
  },

  PLAIN_HTTP: {
    summary: 'Enforce HTTPS for all requests. Redirect HTTP to HTTPS and enable HSTS.',
    detail: `<p>Plain HTTP traffic can be intercepted and modified by anyone on the same network (coffee shop Wi-Fi, corporate proxies, etc.).</p>
<p><strong>Nginx: redirect HTTP to HTTPS:</strong></p>
<pre>server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri;
}</pre>
<p><strong>Express.js: force HTTPS in production:</strong></p>
<pre>app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});</pre>
<p><strong>Also add HSTS</strong> so browsers remember to use HTTPS:</p>
<pre>Strict-Transport-Security: max-age=31536000; includeSubDomains</pre>
<p><strong>Verification:</strong> All entries in a new HAR capture should start with <code>https://</code>.</p>`
  },

  VERBOSE_ERROR: {
    summary: 'Return generic error messages to clients. Log the full detail server-side only.',
    detail: `<p>Stack traces and SQL errors reveal internal file paths, library versions, query structure, and logic. All of this is useful to an attacker planning further exploitation.</p>
<p><strong>Bad (leaks internals):</strong></p>
<pre>HTTP 500
Traceback (most recent call last):
  File "/app/api/users.py", line 42, in get_user
    result = db.query("SELECT * FROM users WHERE id=" + user_id)
AttributeError: 'NoneType' object has no attribute 'query'</pre>
<p><strong>Good (generic response):</strong></p>
<pre>HTTP 500
{ "error": "An unexpected error occurred. Please try again." }</pre>
<p><strong>In Express.js:</strong></p>
<pre>app.use((err, req, res, next) => {
  console.error(err); // log full error server-side
  res.status(500).json({ error: 'An unexpected error occurred.' });
});</pre>
<p><strong>Verification:</strong> Trigger error conditions and confirm responses contain no stack traces or internal details.</p>`
  },

  JWT_IN_RESPONSE: {
    summary: 'Return JWTs only at login. Use short expiry times and prefer HttpOnly cookies for storage.',
    detail: `<p>JWTs returned in JSON response bodies may be logged by API gateways, stored in browser localStorage (XSS risk), or leaked in error logs.</p>
<p><strong>Preferred: set token in an HttpOnly cookie instead of JSON body:</strong></p>
<pre>// Express.js
res.cookie('access_token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',
  maxAge: 15 * 60 * 1000 // 15 minutes
});
res.json({ message: 'Login successful' }); // no token in body</pre>
<p><strong>If returning in body is required (e.g. mobile clients), use short expiry:</strong></p>
<pre>jwt.sign(payload, secret, { expiresIn: '15m' })</pre>
<p><strong>Never store JWTs in localStorage.</strong> Use memory or HttpOnly cookies instead.<br>
<strong>Verification:</strong> Confirm token does not appear in response body for non-login endpoints.</p>`
  },

  PII_IN_URL: {
    summary: 'Remove personal data from URLs. Use request bodies or opaque identifiers instead.',
    detail: `<p>URLs containing emails, NRIC, phone numbers, or PII-named parameters are logged by every intermediary between client and server.</p>
<p><strong>Instead of:</strong></p>
<pre>GET /api/search?email=john@example.com&nric=S1234567A</pre>
<p><strong>Use a POST body:</strong></p>
<pre>POST /api/search
Content-Type: application/json
{ "email": "john@example.com" }</pre>
<p><strong>For resource URLs, use opaque identifiers:</strong></p>
<pre>// Bad
GET /profile/S1234567A

// Good: use an internal UUID instead
GET /profile/a3f2c1d4-8e7b-4a2c-9f1e-2b3c4d5e6f7a</pre>
<p><strong>Verification:</strong> Grep server access logs after the fix to confirm PII no longer appears in URL paths or query strings.</p>`
  },

  MIXED_CONTENT: {
    summary: 'Update all resource URLs to HTTPS. Use the CSP upgrade-insecure-requests directive.',
    detail: `<p>Mixed content (HTTP resources on HTTPS pages) allows network attackers to intercept and tamper with those resources, potentially injecting malicious scripts or styles.</p>
<p><strong>Quick fix: add CSP directive to auto-upgrade HTTP resources:</strong></p>
<pre>Content-Security-Policy: upgrade-insecure-requests</pre>
<p><strong>Proper fix: update all hardcoded HTTP URLs in templates and code:</strong></p>
<pre>// Bad
&lt;script src="http://cdn.example.com/app.js"&gt;&lt;/script&gt;

// Good
&lt;script src="https://cdn.example.com/app.js"&gt;&lt;/script&gt;
// or use protocol-relative
&lt;script src="//cdn.example.com/app.js"&gt;&lt;/script&gt;</pre>
<p><strong>Find mixed content:</strong> Open Chrome DevTools → Console. Mixed content warnings appear as errors when loading the page.</p>
<p><strong>Verification:</strong> No mixed content warnings in the browser console after the fix.</p>`
  },

  COOKIE_NO_SECURE: {
    summary: 'Add the Secure flag to all cookies so they are only sent over HTTPS.',
    detail: `<p>Without the Secure flag, cookies can be transmitted over plain HTTP connections, exposing session tokens to network interception.</p>
<p><strong>Set-Cookie header:</strong></p>
<pre>Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Lax</pre>
<p><strong>Express.js:</strong></p>
<pre>res.cookie('session_id', value, {
  secure: true,      // only sent over HTTPS
  httpOnly: true,
  sameSite: 'lax'
});</pre>
<p><strong>Express session middleware:</strong></p>
<pre>app.use(session({
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }
}));</pre>
<p><strong>Note:</strong> The Secure flag has no effect on localhost. Test with HTTPS in staging.<br>
<strong>Verification:</strong> Recheck the Set-Cookie response headers and confirm <code>Secure</code> is present.</p>`
  },

  COOKIE_NO_HTTPONLY: {
    summary: 'Add the HttpOnly flag to session and auth cookies to prevent JavaScript access.',
    detail: `<p>Without HttpOnly, cookies are readable via <code>document.cookie</code> in JavaScript. An XSS vulnerability anywhere on the page can steal the session token.</p>
<p><strong>Set-Cookie header:</strong></p>
<pre>Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Lax</pre>
<p><strong>Express.js:</strong></p>
<pre>res.cookie('session_id', value, { httpOnly: true, secure: true });</pre>
<p><strong>Spring Boot:</strong></p>
<pre>server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true</pre>
<p><strong>Django:</strong></p>
<pre>SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True</pre>
<p><strong>Note:</strong> Only apply HttpOnly to cookies that do not need to be read by JavaScript (session tokens, auth cookies). Cookies intentionally read by JS (e.g. CSRF tokens) should remain accessible.<br>
<strong>Verification:</strong> In DevTools → Application → Cookies, confirm the HttpOnly column is checked.</p>`
  },

  COOKIE_NO_SAMESITE: {
    summary: 'Add SameSite=Lax or Strict to all cookies to reduce CSRF risk.',
    detail: `<p>Without SameSite, cookies are sent with all cross-site requests including form POSTs from other domains, enabling CSRF attacks.</p>
<p><strong>SameSite values:</strong></p>
<pre>SameSite=Strict  // cookie never sent cross-site (highest security, may break OAuth flows)
SameSite=Lax     // cookie sent on top-level navigation GET only (recommended default)
SameSite=None    // cookie always sent cross-site (requires Secure flag)</pre>
<p><strong>Recommended default:</strong></p>
<pre>Set-Cookie: session_id=abc123; SameSite=Lax; Secure; HttpOnly</pre>
<p><strong>Express.js:</strong></p>
<pre>res.cookie('session_id', value, { sameSite: 'lax', secure: true, httpOnly: true });</pre>
<p><strong>Note:</strong> Use <code>SameSite=None; Secure</code> only for cookies that must be sent in cross-site contexts (e.g. embedded widgets, payment iframes).<br>
<strong>Verification:</strong> In DevTools → Application → Cookies, confirm the SameSite column shows Lax or Strict.</p>`
  },

  MISSING_HEADER_CONTENT_SECURITY_POLICY: {
    summary: "Add a Content-Security-Policy header to restrict what resources the browser can load.",
    detail: `<p>Without CSP, browsers have no restrictions on loading scripts from arbitrary origins, making XSS attacks easier to execute and harder to contain.</p>
<p><strong>Starter policy (restrictive, safe default):</strong></p>
<pre>Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'</pre>
<p><strong>Express.js with helmet:</strong></p>
<pre>const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
  }
}));</pre>
<p><strong>Nginx:</strong></p>
<pre>add_header Content-Security-Policy "default-src 'self';" always;</pre>
<p><strong>Tip:</strong> Start with <code>Content-Security-Policy-Report-Only</code> to test without enforcing. Use <a href="https://csp-evaluator.withgoogle.com" target="_blank">csp-evaluator.withgoogle.com</a> to validate.<br>
<strong>Verification:</strong> Check the response headers in DevTools → Network → response headers.</p>`
  },

  MISSING_HEADER_STRICT_TRANSPORT_SECURITY: {
    summary: 'Add HSTS to instruct browsers to always use HTTPS for your domain.',
    detail: `<p>Without HSTS, a user's first request may go over HTTP (before the 301 redirect), which an attacker can intercept. HSTS tells the browser to always use HTTPS, with no first-request exposure.</p>
<p><strong>Recommended header:</strong></p>
<pre>Strict-Transport-Security: max-age=31536000; includeSubDomains</pre>
<p><strong>Nginx:</strong></p>
<pre>add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;</pre>
<p><strong>Express.js with helmet:</strong></p>
<pre>app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));</pre>
<p><strong>Note:</strong> Only add HSTS on HTTPS responses. Do not add it on HTTP responses.<br>
<strong>Advanced:</strong> Submit to the HSTS preload list (hstspreload.org) to be hardcoded into browsers. Requires <code>max-age=31536000; includeSubDomains; preload</code>.<br>
<strong>Verification:</strong> Check response headers in DevTools for the <code>Strict-Transport-Security</code> header.</p>`
  },

  MISSING_HEADER_X_CONTENT_TYPE_OPTIONS: {
    summary: 'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing.',
    detail: `<p>Without this header, browsers may ignore the declared Content-Type and guess the content type from the response body. An attacker can exploit this to make the browser execute a malicious file as JavaScript.</p>
<p><strong>Header to add:</strong></p>
<pre>X-Content-Type-Options: nosniff</pre>
<p><strong>Nginx:</strong></p>
<pre>add_header X-Content-Type-Options "nosniff" always;</pre>
<p><strong>Express.js with helmet:</strong></p>
<pre>app.use(helmet.noSniff()); // adds X-Content-Type-Options: nosniff</pre>
<p><strong>Note:</strong> This is a simple one-liner fix with no downsides. Add it to all responses.<br>
<strong>Verification:</strong> Check response headers in DevTools. <code>X-Content-Type-Options: nosniff</code> should appear on all responses.</p>`
  },

  MISSING_HEADER_X_FRAME_OPTIONS: {
    summary: 'Add X-Frame-Options to prevent your pages from being embedded in iframes.',
    detail: `<p>Without this header, attackers can embed your pages in iframes on malicious sites and trick users into clicking hidden elements (clickjacking).</p>
<p><strong>Recommended header:</strong></p>
<pre>X-Frame-Options: DENY          // never allow embedding
X-Frame-Options: SAMEORIGIN    // allow embedding only from same origin</pre>
<p><strong>Nginx:</strong></p>
<pre>add_header X-Frame-Options "DENY" always;</pre>
<p><strong>Express.js with helmet:</strong></p>
<pre>app.use(helmet.frameguard({ action: 'deny' }));</pre>
<p><strong>Modern alternative:</strong> use CSP frame-ancestors instead (more flexible):</p>
<pre>Content-Security-Policy: frame-ancestors 'none';</pre>
<p><strong>Note:</strong> If your app has legitimate iframe embedding needs (e.g. embedded in a partner site), use <code>SAMEORIGIN</code> or CSP <code>frame-ancestors</code> with specific origins.<br>
<strong>Verification:</strong> Try embedding your page in an iframe on another page. The browser should block it.</p>`
  },
};

function finding(id, severity, title, detail, evidence, count) {
  const rem = REMEDIATION[id] || null;
  return {
    id, severity, title, detail,
    remediation:       rem?.summary || null,
    remediationDetail: rem?.detail  || null,
    evidence,
    count,
  };
}

function truncateUrl(url, max = 100) {
  if (url.length <= max) return url;
  try {
    const u = new URL(url);
    const base = u.origin + u.pathname;
    return base.length <= max ? base + '...' : base.slice(0, max) + '...';
  } catch {
    return url.slice(0, max) + '...';
  }
}

// Check 1: Auth tokens / API keys in URL query parameters
function checkTokenInUrl(entries) {
  const SENSITIVE_PARAMS = /^(api[_-]?key|apikey|token|access[_-]?token|auth|secret|client[_-]?secret|private[_-]?key|password|passwd|pass|api[_-]?secret)$/i;
  const affected = [];

  for (const e of entries) {
    const params = e.request.queryString.filter(p => SENSITIVE_PARAMS.test(p.name));
    if (params.length) {
      affected.push(`${e.request.method} ${truncateUrl(e.request.url)} (param: ${params.map(p => p.name).join(', ')})`);
    }
  }

  if (!affected.length) return null;
  return finding(
    'TOKEN_IN_URL',
    SEV.high,
    'Sensitive parameter in URL',
    'Auth tokens, API keys, or passwords were found in URL query parameters. These are logged by servers, proxies, and browser history, exposing credentials to unintended parties. Sensitive values should be sent in request headers or the request body instead.',
    affected,
    affected.length
  );
}

// Check 2: Plain HTTP requests
function checkPlainHttp(entries) {
  const affected = entries
    .filter(e => e.request.url.startsWith('http:'))
    .map(e => `${e.request.method} ${truncateUrl(e.request.url)}`);

  if (!affected.length) return null;
  return finding(
    'PLAIN_HTTP',
    SEV.high,
    'Plain HTTP request (non-HTTPS)',
    'One or more requests were made over unencrypted HTTP. Traffic transmitted over HTTP can be intercepted and modified by attackers on the same network. All requests should use HTTPS.',
    affected,
    affected.length
  );
}

// Check 3: Verbose error responses (stack traces, SQL errors)
function checkVerboseErrors(entries) {
  const STACK_PATTERNS = [
    /at\s+[\w$.]+\s*\(/,
    /Traceback \(most recent call last\)/i,
    /NullPointerException/i,
    /undefined method/i,
    /Uncaught\s+(TypeError|ReferenceError|Error)/i,
    /System\.Exception/i,
    /Microsoft\.CSharp/i,
  ];
  const SQL_PATTERNS = [
    /SQL syntax.*near/i,
    /ORA-\d{4,}/,
    /pg_query\(\)/i,
    /mysql_fetch/i,
    /SQLSTATE\[/i,
    /Warning.*mysql_/i,
  ];

  const affected = [];
  for (const e of entries) {
    if (e.response.status < 400) continue;
    const body = e.response.bodyText;
    if (!body) continue;
    const hasStack = STACK_PATTERNS.some(p => p.test(body));
    const hasSql   = SQL_PATTERNS.some(p => p.test(body));
    if (hasStack || hasSql) {
      affected.push(`${e.response.status} ${e.request.method} ${truncateUrl(e.request.url)}`);
    }
  }

  if (!affected.length) return null;
  return finding(
    'VERBOSE_ERROR',
    SEV.high,
    'Verbose error response',
    'Error responses contain stack traces or SQL error messages. This leaks internal implementation details (file paths, library versions, query structure) that help attackers plan further attacks. Errors shown to users should be generic.',
    affected,
    affected.length
  );
}

// Check 4: JWT tokens in response bodies
function checkJwtInResponse(entries) {
  const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
  const affected = [];

  for (const e of entries) {
    if (!e.response.bodyText) continue;
    const matches = e.response.bodyText.match(JWT_RE);
    if (matches) {
      affected.push(`${e.request.method} ${truncateUrl(e.request.url)}`);
    }
  }

  if (!affected.length) return null;
  return finding(
    'JWT_IN_RESPONSE',
    SEV.high,
    'JWT token in response body',
    'JWT tokens were found in response bodies. While expected for login endpoints, JWTs in API responses may be logged by intermediaries or cached by clients. Ensure tokens are only present where expected and are short-lived.',
    affected,
    affected.length
  );
}

// Check 5: PII in URLs
function checkPiiInUrl(entries) {
  const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
  const NRIC_RE  = /\b[STFG]\d{7}[A-Z]\b/;
  const PHONE_RE = /\b(\+65)?[689]\d{7}\b/;
  const PII_PARAMS = /^(nric|ic|ic_number|ssn|passport|dob|date_of_birth|phone|mobile|email)$/i;

  const affected = [];
  for (const e of entries) {
    const url = e.request.url;
    const paramMatch = e.request.queryString.some(p => PII_PARAMS.test(p.name));
    const emailMatch = EMAIL_RE.test(url);
    const nricMatch  = NRIC_RE.test(url);
    const phoneMatch = PHONE_RE.test(url);

    if (paramMatch || emailMatch || nricMatch || phoneMatch) {
      const reasons = [];
      if (emailMatch)  reasons.push('email');
      if (nricMatch)   reasons.push('NRIC');
      if (phoneMatch)  reasons.push('phone');
      if (paramMatch)  reasons.push('PII param name');
      affected.push(`${e.request.method} ${truncateUrl(e.request.url)} (${reasons.join(', ')})`);
    }
  }

  if (!affected.length) return null;
  return finding(
    'PII_IN_URL',
    SEV.high,
    'Personal data in URL',
    'Personally identifiable information (email, NRIC, phone number, or PII-named parameters) was found in request URLs. URLs are logged by web servers, CDNs, and proxies, and may appear in browser history. PII should not be included in URLs.',
    affected,
    affected.length
  );
}

// Check 6: Mixed content
function checkMixedContent(entries) {
  const MIXED_RE = /(?:src|href|action|url)\s*=\s*["']http:\/\//gi;
  const affected = [];

  for (const e of entries) {
    if (!e.request.url.startsWith('https:')) continue;
    if (!e.response.bodyText) continue;
    if (!e.response.contentType.includes('text/html')) continue;
    if (MIXED_RE.test(e.response.bodyText)) {
      affected.push(truncateUrl(e.request.url));
    }
  }

  if (!affected.length) return null;
  return finding(
    'MIXED_CONTENT',
    SEV.medium,
    'Mixed content (HTTP resources on HTTPS page)',
    'HTTPS pages are loading resources (scripts, images, stylesheets) over plain HTTP. Attackers can intercept and tamper with these HTTP resources to inject malicious content into otherwise secure pages.',
    affected,
    affected.length
  );
}

// Check 7: Cookies missing Secure flag
function checkCookieSecure(entries) {
  const affected = [];
  const seen = new Set();

  for (const e of entries) {
    for (const c of e.response.cookies) {
      const key = `${c.name}@${new URL(e.request.url).hostname}`;
      if (seen.has(key)) continue;
      if (c.secure === false || c.secure === undefined || c.secure === '') {
        seen.add(key);
        affected.push(`${c.name} (${new URL(e.request.url).hostname})`);
      }
    }
  }

  if (!affected.length) return null;
  return finding(
    'COOKIE_NO_SECURE',
    SEV.medium,
    'Cookie missing Secure flag',
    'One or more cookies are set without the Secure flag. Without this flag, the cookie can be transmitted over plain HTTP connections, exposing session tokens or other sensitive values to network interception.',
    affected,
    affected.length
  );
}

// Check 8: Cookies missing HttpOnly flag
function checkCookieHttpOnly(entries) {
  const affected = [];
  const seen = new Set();

  for (const e of entries) {
    for (const c of e.response.cookies) {
      const key = `${c.name}@${new URL(e.request.url).hostname}`;
      if (seen.has(key)) continue;
      if (c.httpOnly === false || c.httpOnly === undefined || c.httpOnly === '') {
        seen.add(key);
        affected.push(`${c.name} (${new URL(e.request.url).hostname})`);
      }
    }
  }

  if (!affected.length) return null;
  return finding(
    'COOKIE_NO_HTTPONLY',
    SEV.medium,
    'Cookie missing HttpOnly flag',
    'One or more cookies are set without the HttpOnly flag. Without this flag, the cookie is accessible via JavaScript, making it vulnerable to theft through XSS attacks.',
    affected,
    affected.length
  );
}

// Check 9: Missing security response headers
function checkSecurityHeaders(entries) {
  const HEADERS = [
    { name: 'content-security-policy',   label: 'Content-Security-Policy',   severity: SEV.medium },
    { name: 'strict-transport-security', label: 'Strict-Transport-Security',  severity: SEV.medium },
    { name: 'x-content-type-options',    label: 'X-Content-Type-Options',     severity: SEV.medium },
    { name: 'x-frame-options',           label: 'X-Frame-Options',            severity: SEV.medium },
  ];

  const results = [];

  for (const h of HEADERS) {
    const hosts = new Set();
    let count = 0;

    for (const e of entries) {
      if (e.response.status === 0) continue;
      if (!e.response.headerMap[h.name]) {
        try { hosts.add(new URL(e.request.url).hostname); } catch { /* skip */ }
        count++;
      }
    }

    if (!hosts.size) continue;

    results.push(finding(
      `MISSING_HEADER_${h.name.toUpperCase().replace(/-/g, '_')}`,
      h.severity,
      `Missing ${h.label} header`,
      `Responses are missing the ${h.label} security header. ${headerDescription(h.name)}`,
      [...hosts],
      count
    ));
  }

  return results;
}

function headerDescription(name) {
  const map = {
    'content-security-policy':   'Without CSP, browsers have no restrictions on what scripts or resources can be loaded, making XSS attacks easier to execute.',
    'strict-transport-security': 'Without HSTS, browsers may allow HTTP connections, enabling downgrade attacks and traffic interception.',
    'x-content-type-options':    'Without this header, browsers may sniff response content types, potentially executing malicious content.',
    'x-frame-options':           'Without this header, pages can be embedded in iframes on other sites, enabling clickjacking attacks.',
  };
  return map[name] || '';
}

// Check 10: Cookies missing SameSite attribute
function checkCookieSameSite(entries) {
  const affected = [];
  const seen = new Set();

  for (const e of entries) {
    for (const c of e.response.cookies) {
      const key = `${c.name}@${new URL(e.request.url).hostname}`;
      if (seen.has(key)) continue;
      if (!c.sameSite || c.sameSite === '') {
        seen.add(key);
        affected.push(`${c.name} (${new URL(e.request.url).hostname})`);
      }
    }
  }

  if (!affected.length) return null;
  return finding(
    'COOKIE_NO_SAMESITE',
    SEV.low,
    'Cookie missing SameSite attribute',
    'One or more cookies are set without a SameSite attribute. Without SameSite, cookies are sent with cross-site requests, increasing the risk of CSRF attacks. Recommended value: SameSite=Lax or SameSite=Strict.',
    affected,
    affected.length
  );
}

function runAllChecks(entries) {
  const findings = [];

  const checks = [
    checkTokenInUrl,
    checkPlainHttp,
    checkVerboseErrors,
    checkJwtInResponse,
    checkPiiInUrl,
    checkMixedContent,
    checkCookieSecure,
    checkCookieHttpOnly,
    checkCookieSameSite,
  ];

  for (const check of checks) {
    const result = check(entries);
    if (result) findings.push(result);
  }

  const headerFindings = checkSecurityHeaders(entries);
  findings.push(...headerFindings);

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return findings;
}

module.exports = { runAllChecks };
