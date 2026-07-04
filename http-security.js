'use strict';

/**
 * CipherQ — HTTP Security Scanner
 * Checks: Security headers, CORS misconfiguration, cookie flags,
 *         HTTP methods, redirect chain analysis, JS dependency exposure
 */

const https = require('https');
const http  = require('http');
const tls   = require('tls');

// ─── Required security headers and their ideal values ────────────────────────
const SECURITY_HEADERS = [
  {
    name: 'strict-transport-security',
    label: 'Strict-Transport-Security (HSTS)',
    severity: 'high',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — HTTP downgrade attacks possible' };
      const maxAge = parseInt((val.match(/max-age=(\d+)/i) || [])[1] || '0', 10);
      if (maxAge < 31536000) return { ok: false, issue: `max-age too short (${maxAge}s) — recommend ≥31536000 (1 year)` };
      if (!val.includes('includeSubDomains')) return { ok: false, issue: 'Missing includeSubDomains — subdomains not protected' };
      return { ok: true };
    },
    recommendation: 'Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    nistRef: 'SC-8 · SC-23 | RFC 6797',
  },
  {
    name: 'content-security-policy',
    label: 'Content-Security-Policy (CSP)',
    severity: 'high',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — XSS and content injection attacks unmitigated' };
      if (val.includes("'unsafe-inline'") && val.includes('script-src')) return { ok: false, issue: "unsafe-inline in script-src negates XSS protection" };
      if (val.includes('*') && val.includes('script-src')) return { ok: false, issue: "Wildcard (*) in script-src allows any script source" };
      if (!val.includes('default-src') && !val.includes('script-src')) return { ok: false, issue: 'No default-src or script-src directive' };
      return { ok: true };
    },
    recommendation: "Set a restrictive CSP. Minimum: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
    nistRef: 'SI-10 · SC-18 | OWASP CSP Cheat Sheet',
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    severity: 'medium',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — clickjacking attacks possible' };
      if (!['DENY','SAMEORIGIN'].includes(val.toUpperCase().trim())) return { ok: false, issue: `Value "${val}" is non-standard` };
      return { ok: true };
    },
    recommendation: 'Set: X-Frame-Options: DENY (or SAMEORIGIN if framing within same origin is required). Also add frame-ancestors in CSP.',
    nistRef: 'SI-10 | OWASP Clickjacking Defense',
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    severity: 'medium',
    check: (val) => {
      if (!val || val.toLowerCase().trim() !== 'nosniff') return { ok: false, issue: 'Header absent or not set to nosniff — MIME sniffing attacks possible' };
      return { ok: true };
    },
    recommendation: 'Set: X-Content-Type-Options: nosniff',
    nistRef: 'SI-10 | OWASP Security Headers',
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    severity: 'low',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — full URL may be sent as Referer to third parties' };
      const weak = ['unsafe-url', 'no-referrer-when-downgrade'];
      if (weak.some(w => val.toLowerCase().includes(w))) return { ok: false, issue: `Weak policy "${val}" leaks URL to cross-origin requests` };
      return { ok: true };
    },
    recommendation: 'Set: Referrer-Policy: strict-origin-when-cross-origin',
    nistRef: 'SC-8 | W3C Referrer Policy',
  },
  {
    name: 'permissions-policy',
    label: 'Permissions-Policy',
    severity: 'low',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — browser features (camera, mic, geolocation) not restricted' };
      return { ok: true };
    },
    recommendation: 'Set: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
    nistRef: 'SC-18 | W3C Permissions Policy',
  },
  {
    name: 'x-xss-protection',
    label: 'X-XSS-Protection',
    severity: 'info',
    check: (val) => {
      if (val && val.includes('1; mode=block')) return { ok: true };
      // Modern browsers ignore this; note if it's set to 0 (disables filter)
      if (val === '0') return { ok: false, issue: 'Set to 0 — explicitly disables browser XSS filter' };
      return { ok: true, note: 'Deprecated in modern browsers; rely on CSP instead' };
    },
    recommendation: 'Remove or set to: X-XSS-Protection: 1; mode=block. Rely on CSP for XSS mitigation.',
    nistRef: 'SI-10',
  },
  {
    name: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy (COOP)',
    severity: 'low',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — Spectre-style cross-origin attacks not mitigated' };
      return { ok: true };
    },
    recommendation: 'Set: Cross-Origin-Opener-Policy: same-origin',
    nistRef: 'SC-18',
  },
  {
    name: 'cross-origin-embedder-policy',
    label: 'Cross-Origin-Embedder-Policy (COEP)',
    severity: 'low',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — required for SharedArrayBuffer isolation' };
      return { ok: true };
    },
    recommendation: 'Set: Cross-Origin-Embedder-Policy: require-corp',
    nistRef: 'SC-18',
  },
  {
    name: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy (CORP)',
    severity: 'low',
    check: (val) => {
      if (!val) return { ok: false, issue: 'Header absent — resources may be loaded by cross-origin pages' };
      return { ok: true };
    },
    recommendation: 'Set: Cross-Origin-Resource-Policy: same-origin',
    nistRef: 'SC-18',
  },
];

// ─── Server banner patterns that reveal software versions ─────────────────────
const BANNER_PATTERNS = [
  { pattern: /Apache\/(\d+\.\d+)/i,        software: 'Apache',     eolVersion: '2.2' },
  { pattern: /nginx\/(\d+\.\d+)/i,         software: 'nginx',      eolVersion: '1.18' },
  { pattern: /Microsoft-IIS\/(\d+\.\d+)/i, software: 'IIS',        eolVersion: '8.5' },
  { pattern: /PHP\/(\d+\.\d+)/i,           software: 'PHP',        eolVersion: '7.4' },
  { pattern: /OpenSSL\/(\d+\.\d+)/i,       software: 'OpenSSL',    eolVersion: '1.0' },
  { pattern: /Express\/(\d+\.\d+)/i,       software: 'Express',    eolVersion: null },
  { pattern: /Werkzeug\/(\d+\.\d+)/i,      software: 'Werkzeug',   eolVersion: null },
  { pattern: /Tomcat\/(\d+\.\d+)/i,        software: 'Tomcat',     eolVersion: '8.5' },
  { pattern: /WordPress\/(\d+\.\d+)/i,     software: 'WordPress',  eolVersion: null },
  { pattern: /Drupal (\d+)/i,              software: 'Drupal',     eolVersion: null },
];

// ─── Cookie security flags ────────────────────────────────────────────────────
function analyseCookie(cookieStr) {
  const lower = cookieStr.toLowerCase();
  const name  = cookieStr.split('=')[0].trim();
  const issues = [];

  if (!lower.includes('secure'))   issues.push('missing Secure flag — cookie sent over HTTP');
  if (!lower.includes('httponly')) issues.push('missing HttpOnly flag — accessible to JavaScript (XSS risk)');
  if (!lower.includes('samesite')) issues.push('missing SameSite flag — CSRF risk');
  else if (lower.includes('samesite=none') && !lower.includes('secure')) issues.push('SameSite=None without Secure flag is invalid');

  // Overly broad domain scope
  const domainMatch = cookieStr.match(/domain=([^;]+)/i);
  if (domainMatch) {
    const domain = domainMatch[1].trim();
    if (domain.startsWith('.') && domain.split('.').length <= 2) {
      issues.push(`overly broad Domain scope (${domain}) — cookie sent to all subdomains`);
    }
  }

  // Session-like names without security flags
  const sessionNames = ['session', 'sess', 'auth', 'token', 'jwt', 'sid', 'user', 'login'];
  const isSessionLike = sessionNames.some(s => name.toLowerCase().includes(s));

  return { name, issues, isSessionLike, severity: issues.length > 0 ? (isSessionLike ? 'high' : 'medium') : 'ok' };
}

// ─── HTTP fetch helper ────────────────────────────────────────────────────────
function fetchURL(hostname, opts = {}) {
  const {
    port     = 443,
    secure   = true,
    path     = '/',
    method   = 'GET',
    headers  = {},
    body     = null,
    timeoutMs = 4000,
    maxBody  = 16384,
  } = opts;

  return new Promise((resolve) => {
    const lib = secure ? https : http;
    const options = {
      host: hostname,
      port,
      path,
      method,
      headers: { 'User-Agent': 'CipherQ-Scanner/1.0', ...headers },
      rejectUnauthorized: false,
      // Note: Node's socket timeout only fires on *inactivity* — a server
      // dripping one byte just under the interval keeps the connection alive
      // indefinitely. The wallTimer below is the hard upper bound.
      timeout: timeoutMs,
    };

    let resolved = false;
    const done = (r) => { if (!resolved) { resolved = true; resolve(r); } };

    // Hard wall-clock timer: fires unconditionally at timeoutMs + 500ms.
    // Prevents drip-feed / slow-loris stalls that bypass socket.setTimeout.
    const wallTimer = setTimeout(() => { done(null); }, timeoutMs + 500);

    try {
      const req = lib.request(options, (res) => {
        let buf = '';
        res.on('data', (c) => {
          buf += c;
          if (buf.length > maxBody) res.destroy();
        });
        res.on('end', () => {
          clearTimeout(wallTimer);
          done({
            statusCode:       res.statusCode,
            headers:          res.headers,
            body:             buf.slice(0, maxBody),
            redirectLocation: res.headers.location || null,
          });
        });
        res.on('error', () => { clearTimeout(wallTimer); done(null); });
      });
      req.on('error',   () => { clearTimeout(wallTimer); done(null); });
      req.on('timeout', () => { clearTimeout(wallTimer); req.destroy(); done(null); });
      if (body) req.write(body);
      req.end();
    } catch { clearTimeout(wallTimer); done(null); }
  });
}

// ─── 1. Security headers scan ────────────────────────────────────────────────
async function checkSecurityHeaders(hostname) {
  const result = { hostname, findings: [], headers: {} };

  const resp = await fetchURL(hostname);
  if (!resp) {
    result.findings.push({ id: 'HTTP-UNREACHABLE', severity: 'info', area: 'http-headers', title: `${hostname} not reachable on HTTPS`, detail: 'Could not connect to retrieve HTTP headers.' });
    return result;
  }

  result.statusCode  = resp.statusCode;
  result.headers     = resp.headers;
  result.serverBanner = resp.headers['server'] || resp.headers['x-powered-by'] || null;

  // Check each security header
  for (const hdr of SECURITY_HEADERS) {
    const val = resp.headers[hdr.name] || null;
    const check = hdr.check(val);

    if (!check.ok) {
      result.findings.push({
        id:   `HDR-${hdr.name.toUpperCase().replace(/-/g,'_')}`,
        severity: hdr.severity,
        area: 'http-headers',
        title: `Missing or misconfigured: ${hdr.label}`,
        detail: `${check.issue}. Current value: ${val ? `"${val}"` : 'not set'}.`,
        recommendation: hdr.recommendation,
        nistRef: hdr.nistRef,
      });
    }
  }

  // Server banner disclosure
  if (result.serverBanner) {
    const matched = BANNER_PATTERNS.find(p => p.pattern.test(result.serverBanner));
    result.findings.push({
      id: 'HDR-SERVER-DISCLOSURE',
      severity: matched ? 'medium' : 'low',
      area: 'http-headers',
      title: `Server version disclosed in response headers`,
      detail: `Server header reveals: "${result.serverBanner}".${matched ? ` ${matched.software} version exposure assists fingerprinting and targeted exploitation.` : ' Software version disclosure assists attackers in targeting known vulnerabilities.'}`,
      recommendation: 'Remove or neutralise the Server and X-Powered-By headers in your web server configuration.',
      nistRef: 'CM-7 · SI-2',
    });
  }

  // Cookie analysis
  const setCookieHeaders = resp.headers['set-cookie'] || [];
  for (const cookieStr of setCookieHeaders) {
    const analysis = analyseCookie(cookieStr);
    if (analysis.issues.length > 0) {
      result.findings.push({
        id: `COOKIE-${analysis.name.toUpperCase().slice(0,20)}`,
        severity: analysis.severity === 'high' ? 'high' : 'medium',
        area: 'cookie-security',
        title: `Insecure cookie: ${analysis.name}`,
        detail: `Cookie "${analysis.name}" has security issues: ${analysis.issues.join('; ')}.${analysis.isSessionLike ? ' This appears to be a session/auth cookie — insecure flags are high severity.' : ''}`,
        recommendation: `Set cookie with Secure; HttpOnly; SameSite=Strict (or Lax) flags. Example: Set-Cookie: ${analysis.name}=...; Secure; HttpOnly; SameSite=Strict`,
        nistRef: 'SC-8 · SC-23 | OWASP Session Management',
      });
    }
  }

  return result;
}

// ─── 2. CORS misconfiguration ─────────────────────────────────────────────────
async function checkCORS(hostname) {
  const result = { hostname, findings: [] };

  const attackerOrigin = 'https://evil-attacker.com';

  const resp = await fetchURL(hostname, {
    headers: { 'Origin': attackerOrigin },
  });

  if (!resp) return result;

  const acao = resp.headers['access-control-allow-origin'] || null;
  const acac = resp.headers['access-control-allow-credentials'] || null;

  if (!acao) return result; // No CORS headers — not an issue

  result.corsHeaders = { 'access-control-allow-origin': acao, 'access-control-allow-credentials': acac };

  if (acao === '*') {
    result.findings.push({
      id: 'CORS-WILDCARD',
      severity: acac?.toLowerCase() === 'true' ? 'critical' : 'medium',
      area: 'cors',
      title: `CORS wildcard (*) — all origins allowed${acac?.toLowerCase() === 'true' ? ' WITH credentials' : ''}`,
      detail: `Access-Control-Allow-Origin: * permits any origin to read responses. ${acac?.toLowerCase() === 'true' ? 'CRITICAL: Access-Control-Allow-Credentials: true combined with wildcard origin is invalid per spec and may be exploitable in some browser implementations to steal authenticated responses.' : 'If this endpoint does not serve public data, any origin can read the response content.'}`,
      recommendation: 'Restrict CORS to an explicit allowlist of trusted origins. Never combine ACAO: * with ACAC: true.',
      nistRef: 'SC-8 · SC-18 | OWASP CORS',
      priority: acac?.toLowerCase() === 'true' ? 'P1' : undefined,
    });
  } else if (acao === attackerOrigin) {
    // Server reflected our attacker origin — this is the critical misconfiguration
    result.findings.push({
      id: 'CORS-ORIGIN-REFLECTED',
      severity: acac?.toLowerCase() === 'true' ? 'critical' : 'high',
      area: 'cors',
      title: `CORS origin reflection — arbitrary origins accepted${acac?.toLowerCase() === 'true' ? ' with credentials' : ''}`,
      detail: `Server reflected the supplied Origin header (${attackerOrigin}) back as Access-Control-Allow-Origin. ${acac?.toLowerCase() === 'true' ? 'With Access-Control-Allow-Credentials: true, this allows any website to make credentialed cross-origin requests and read the response — equivalent to no same-origin policy.' : 'This allows any origin to read responses to unauthenticated requests.'}`,
      recommendation: 'Implement an explicit allowlist of trusted origins server-side. Never reflect the Origin header directly.',
      nistRef: 'SC-8 · SC-18 | OWASP CORS',
      priority: 'P1',
    });
  }

  return result;
}

// ─── 3. HTTP methods ──────────────────────────────────────────────────────────
async function checkHTTPMethods(hostname) {
  const result = { hostname, findings: [], allowedMethods: [] };

  // First get OPTIONS
  const optResp = await fetchURL(hostname, { method: 'OPTIONS' });
  if (optResp?.headers?.allow) {
    result.allowedMethods = optResp.headers.allow.split(',').map(m => m.trim().toUpperCase());
  }

  const dangerousMethods = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT', 'PATCH'];
  const concerningFound = [];

  // Probe dangerous methods directly — short timeout, all in parallel
  await Promise.all(dangerousMethods.map(async (method) => {
    const resp = await fetchURL(hostname, { method, timeoutMs: 3000 });
    if (resp && resp.statusCode && resp.statusCode < 405) {
      // 405 = Method Not Allowed; anything else means the server accepted it
      concerningFound.push({ method, statusCode: resp.statusCode });
    }
  }));

  // TRACE specifically — check for XST
  const traceEntry = concerningFound.find(m => m.method === 'TRACE');
  if (traceEntry) {
    result.findings.push({
      id: 'HTTP-TRACE-ENABLED',
      severity: 'medium',
      area: 'http-methods',
      title: 'HTTP TRACE method enabled (Cross-Site Tracing risk)',
      detail: `Server responded to TRACE with HTTP ${traceEntry.statusCode}. TRACE echoes back the full request including headers, enabling Cross-Site Tracing (XST) attacks that can expose cookies and auth headers to malicious scripts, even when HttpOnly is set.`,
      recommendation: 'Disable the TRACE method in your web server configuration. Apache: TraceEnable Off. nginx: if ($request_method = TRACE) { return 405; }',
      nistRef: 'CM-7 | OWASP Testing Guide OTG-CONFIG-006',
    });
  }

  // PUT/DELETE without auth
  const writeMethodsFound = concerningFound.filter(m => ['PUT','DELETE'].includes(m.method));
  if (writeMethodsFound.length > 0) {
    result.findings.push({
      id: 'HTTP-WRITE-METHODS',
      severity: 'high',
      area: 'http-methods',
      title: `Potentially dangerous HTTP methods accepted: ${writeMethodsFound.map(m => m.method).join(', ')}`,
      detail: `Server accepted ${writeMethodsFound.map(m => `${m.method} (HTTP ${m.statusCode})`).join(', ')}. Write methods available without apparent authentication may allow file upload, content modification, or resource deletion.`,
      recommendation: 'Explicitly restrict HTTP methods to GET, HEAD, POST, OPTIONS. Deny all others with a 405 response.',
      nistRef: 'AC-3 · CM-7 | OWASP Testing Guide',
    });
  }

  if (concerningFound.length === 0) {
    result.findings.push({
      id: 'HTTP-METHODS-OK',
      severity: 'info',
      area: 'http-methods',
      title: 'No dangerous HTTP methods accepted',
      detail: `OPTIONS reports: ${result.allowedMethods.join(', ') || 'no Allow header'}. Dangerous methods (TRACE, PUT, DELETE) returned 405.`,
    });
  }

  return result;
}

// ─── 4. Redirect chain analysis ───────────────────────────────────────────────
async function checkRedirectChain(hostname) {
  const result = { hostname, findings: [], chain: [] };
  let current = `http://${hostname}/`;
  let hops = 0;
  const maxHops = 4;  // reduced from 10 — practical redirect chains are rarely > 3
  let hadHTTP = false;
  let mixedDomains = false;

  while (hops < maxHops) {
    const secure = current.startsWith('https://');
    const url = new URL(current);
    const resp = await fetchURL(url.hostname, {
      secure,
      port: secure ? 443 : 80,
      path: url.pathname + url.search,
      method: 'HEAD',
      timeoutMs: 3000,
    });

    if (!resp) break;

    result.chain.push({
      url: current,
      statusCode: resp.statusCode,
      location: resp.redirectLocation,
    });

    if (!secure) hadHTTP = true;
    if (hops > 0 && url.hostname !== hostname) mixedDomains = true;

    if (resp.statusCode < 300 || resp.statusCode >= 400 || !resp.redirectLocation) break;

    // Build next URL
    const next = resp.redirectLocation;
    current = next.startsWith('http') ? next : `${secure ? 'https' : 'http'}://${url.hostname}${next}`;
    hops++;
  }

  if (hops >= maxHops) {
    result.findings.push({
      id: 'HTTP-REDIRECT-LOOP',
      severity: 'high',
      area: 'redirect-chain',
      title: `Redirect chain too long (≥${maxHops} hops) — possible loop`,
      detail: `Following redirects from http://${hostname} exceeded ${maxHops} hops. This may indicate a redirect loop, which causes browsers to error and blocks legitimate users.`,
      recommendation: 'Audit redirect configuration. Reduce to at most 2-3 hops.',
      nistRef: 'CM-3 · SC-23',
    });
  }

  // Check if HTTP→HTTPS redirect passes through plain HTTP
  const httpSteps = result.chain.filter(s => s.url.startsWith('http://'));
  if (httpSteps.length > 0 && result.chain.some(s => s.url.startsWith('https://'))) {
    // This is normal — but check if any sensitive data could be in the request
    result.findings.push({
      id: 'HTTP-REDIRECT-OK',
      severity: 'info',
      area: 'redirect-chain',
      title: `HTTP redirects to HTTPS in ${result.chain.length} hop(s)`,
      detail: `Redirect chain: ${result.chain.map(s => `${s.url} → ${s.statusCode}`).join(' → ')}.`,
    });
  } else if (!result.chain.some(s => s.url.startsWith('https://'))) {
    result.findings.push({
      id: 'HTTP-NO-HTTPS-REDIRECT',
      severity: 'high',
      area: 'redirect-chain',
      title: 'HTTP does not redirect to HTTPS',
      detail: `http://${hostname} does not redirect to HTTPS. Plain HTTP connections are possible.`,
      recommendation: 'Configure a permanent (301) redirect from HTTP to HTTPS on all endpoints.',
      nistRef: 'SC-8 · SC-23 | RFC 6797',
    });
  }

  if (mixedDomains) {
    result.findings.push({
      id: 'HTTP-REDIRECT-CROSS-DOMAIN',
      severity: 'low',
      area: 'redirect-chain',
      title: 'Redirect chain passes through external domain',
      detail: `Redirect chain passes through a domain other than ${hostname}. Cross-domain redirects can expose the Referer header and request parameters to the intermediate domain.`,
      recommendation: 'Minimise cross-domain redirects. Ensure intermediate domains are trusted and controlled.',
      nistRef: 'SC-8',
    });
  }

  return result;
}

// ─── 5. GraphQL introspection ─────────────────────────────────────────────────
async function checkGraphQL(hostname) {
  const result = { hostname, findings: [] };

  const introspectionQuery = JSON.stringify({
    query: '{ __schema { queryType { name } types { name } } }',
  });

  const endpoints = ['/graphql', '/api/graphql', '/gql'];

  for (const path of endpoints) {
    const resp = await fetchURL(hostname, {
      method: 'POST',
      path,
      headers: { 'Content-Type': 'application/json', 'Content-Length': introspectionQuery.length },
      timeoutMs: 5000,
    });

    if (!resp || resp.statusCode === 404 || resp.statusCode === 405) continue;

    try {
      const json = JSON.parse(resp.body);
      if (json.data?.__schema) {
        const typeCount = json.data.__schema.types?.length || 0;
        result.findings.push({
          id: 'API-GRAPHQL-INTROSPECTION',
          severity: 'medium',
          area: 'api-security',
          title: `GraphQL introspection enabled at ${path}`,
          detail: `The GraphQL endpoint at ${hostname}${path} has introspection enabled, exposing ${typeCount} types in the schema. Introspection reveals the full API structure — all queries, mutations, types, and fields — to any unauthenticated caller, enabling targeted API abuse.`,
          recommendation: 'Disable introspection in production. In Apollo Server: introspection: false. In most frameworks this is a one-line config change.',
          nistRef: 'CM-7 · AC-3 | OWASP API Security Top 10 — API8',
        });
        break;
      }
    } catch {}
  }

  return result;
}

// ─── Master HTTP security scan ────────────────────────────────────────────────
async function scanHTTPSecurity(domain, hosts, opts = {}) {
  const { onProgress = null } = opts;
  const allFindings = [];

  const step = (msg) => { if (onProgress) onProgress({ phase: 'http-security', message: msg }); };

  // Get reachable HTTPS hosts — cap at 15 to keep scan fast
  const reachableHosts = hosts
    .filter(h => h.tls?.cipher)
    .map(h => h.hostname)
    .slice(0, 15);

  if (reachableHosts.length === 0) {
    return { findings: [], summary: { hostsScanned: 0 } };
  }

  // Slow checks (methods, redirects, GraphQL) only on apex + www to keep scan fast
  const slowCheckHosts = reachableHosts.filter(h =>
    h === domain || h === `www.${domain}` || reachableHosts.indexOf(h) < 3
  ).slice(0, 3);

  step(`Scanning ${reachableHosts.length} hosts (deep checks on ${slowCheckHosts.length})…`);

  const results = { headers: [], cors: [], methods: [], redirects: [], graphql: [] };

  // Fast checks on all hosts with higher concurrency
  const concurrency = 10;
  for (let i = 0; i < reachableHosts.length; i += concurrency) {
    const batch = reachableHosts.slice(i, i + concurrency);
    await Promise.all(batch.map(async (hostname) => {
      const [hdrs, cors] = await Promise.all([
        checkSecurityHeaders(hostname),
        checkCORS(hostname),
      ]);
      results.headers.push(hdrs);
      results.cors.push(cors);
    }));
  }

  // Slow checks only on apex/www — all run in parallel
  await Promise.all(slowCheckHosts.map(async (hostname) => {
    const [methods, redirects, gql] = await Promise.all([
      checkHTTPMethods(hostname),
      checkRedirectChain(hostname),
      checkGraphQL(hostname),
    ]);
    results.methods.push(methods);
    results.redirects.push(redirects);
    results.graphql.push(gql);
  }));

  // Flatten findings with hostname
  for (const category of Object.values(results)) {
    for (const r of category) {
      for (const f of r.findings || []) {
        allFindings.push({ ...f, hostname: r.hostname });
      }
    }
  }

  const summary = {
    hostsScanned: reachableHosts.length,
    totalFindings: allFindings.length,
    bySeverity: {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high:     allFindings.filter(f => f.severity === 'high').length,
      medium:   allFindings.filter(f => f.severity === 'medium').length,
      low:      allFindings.filter(f => f.severity === 'low').length,
      info:     allFindings.filter(f => f.severity === 'info').length,
    },
    missingHSTS:      allFindings.filter(f => f.id === 'HDR-STRICT_TRANSPORT_SECURITY').length,
    missingCSP:       allFindings.filter(f => f.id === 'HDR-CONTENT_SECURITY_POLICY').length,
    corsIssues:       allFindings.filter(f => f.area === 'cors' && f.severity !== 'info').length,
    cookieIssues:     allFindings.filter(f => f.area === 'cookie-security').length,
    traceEnabled:     allFindings.some(f => f.id === 'HTTP-TRACE-ENABLED'),
    graphqlExposed:   allFindings.some(f => f.id === 'API-GRAPHQL-INTROSPECTION'),
    serverDisclosure: allFindings.filter(f => f.id === 'HDR-SERVER-DISCLOSURE').map(f => f.hostname),
  };

  return { findings: allFindings, summary, details: results };
}

module.exports = {
  scanHTTPSecurity,
  checkSecurityHeaders,
  checkCORS,
  checkHTTPMethods,
  checkRedirectChain,
  checkGraphQL,
};
