'use strict';

/**
 * CipherQ PQC Scanner — API Server  (v2.2)
 *
 * Changes from v2.1:
 *   • API key authentication (CIPHERQ_API_KEYS) on every state-changing and
 *     data-returning endpoint — v2.1 had NO authentication at all, meaning
 *     any internet caller could drive active scans against third-party
 *     infrastructure from this server's IP. Fails closed if unconfigured.
 *   • CBOM/vendor storage is now tenant-namespaced (see cbom.js) — v2.1's
 *     GET /api/cbom/board-metrics/:domain returned any tenant's stored data
 *     for a given domain name to any caller with no authorisation check.
 *   • Rate limiting keyed by tenant (API key) rather than source IP alone.
 *   • Internal Discovery (/api/internal/code-scan, /api/internal/pki-scan)
 *     now requires an operator-configured, realpath-validated allowlist
 *     (CIPHERQ_INTERNAL_SCAN_ROOTS) instead of a denylist of a few system
 *     paths — the prior version was an arbitrary-file-read primitive on an
 *     unauthenticated endpoint.
 *
 * Changes from v2.0:
 *   • SSRF guard on all domain inputs (blocks RFC-1918, loopback, link-local)
 *   • Helmet HTTP security headers
 *   • Rate limiting (express-rate-limit) — scan endpoints capped at 20 req/15min per IP
 *   • Job Map TTL cleanup — prevents unbounded memory growth on Render
 *   • /api/cbom/persist + /api/cbom/board-metrics/:domain   (CBOM Dashboard)
 *   • /api/vendor, /api/vendor/assess, /api/vendor/assess/:jobId  (Vendor Scorecard)
 *   • /api/internal/code-scan + /api/internal/pki-scan  (Internal Discovery)
 *   • /api/report extended to include boardMetrics, codeData, pkiData, vendorData
 *   • Domain validation tightened to a single compiled regex
 *   • /api/ai-scan removed (USE_API_SIMULATION=false in UI; key must not be proxied openly)
 */

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const https   = require('https');

const { scanDomain, analyseHost, generateSubdomains } = require('./scanner');
const { assertScannable } = require('./ssrf-guard');
const { persistScan, getBoardMetrics, listVendors }   = require('./cbom');
const { startVendorAssessment, getVendorJob }         = require('./vendor');
const { runCodeScan, runPKIScan }                     = require('./internal-scanner');

const app = express();

// ─── Internal Discovery — allowlisted roots ──────────────────────────────────
// Internal Discovery (code/SCA + PKI scan) previously accepted ANY absolute
// filesystem path from an unauthenticated request body, denylisting only a
// handful of obviously-dangerous system paths (/proc, /sys, /dev,
// /etc/shadow, /etc/passwd). On an endpoint with no auth, that's an
// arbitrary-file-read primitive: /etc/ssl/private, ~/.ssh, the app's own
// .env, and (via the code-scan rules, which are *designed* to match
// "-----BEGIN ... PRIVATE KEY-----") the first 200 characters of any private
// key the process could read were all in reach.
//
// Fix: require an explicit, operator-configured allowlist of roots
// (CIPHERQ_INTERNAL_SCAN_ROOTS, colon-separated absolute paths), and
// realpath-resolve both the allowlist and every incoming request path
// before checking containment — path.resolve() alone only normalises
// `.`/`..` lexically, it does not follow symlinks, so a symlink planted
// inside (or passed as) rootPath could otherwise escape a naive prefix
// check. If the env var isn't set, the feature is disabled with a clear
// error rather than silently allowing arbitrary paths.
const INTERNAL_SCAN_ALLOWED_ROOTS = (process.env.CIPHERQ_INTERNAL_SCAN_ROOTS || '')
  .split(':')
  .map(p => p.trim())
  .filter(Boolean)
  .map(p => {
    try { return fs.realpathSync(p); } catch { return null; }
  })
  .filter(Boolean);

/**
 * Validate an incoming rootPath against the configured allowlist.
 * Returns the realpath-resolved, contained path.
 * @throws Error with a message safe to return to the caller (400-class)
 */
function validateInternalScanPath(rootPath) {
  if (!rootPath || typeof rootPath !== 'string') {
    throw new Error('rootPath is required');
  }
  if (!path.isAbsolute(rootPath)) {
    throw new Error('rootPath must be an absolute path');
  }
  if (INTERNAL_SCAN_ALLOWED_ROOTS.length === 0) {
    throw new Error(
      'Internal Discovery is disabled: no allowlisted roots configured. ' +
      'Set CIPHERQ_INTERNAL_SCAN_ROOTS (colon-separated absolute paths) in the ' +
      'server environment to enable scanning specific directories.'
    );
  }

  let real;
  try {
    real = fs.realpathSync(rootPath);
  } catch (e) {
    throw new Error(`Path does not exist or is not readable: ${rootPath}`);
  }

  const contained = INTERNAL_SCAN_ALLOWED_ROOTS.some(
    root => real === root || real.startsWith(root + path.sep)
  );
  if (!contained) {
    throw new Error(
      `Refused: "${rootPath}" (resolved to "${real}") is not within an allowlisted Internal Discovery root.`
    );
  }

  return real;
}

// ─── Security middleware ──────────────────────────────────────────────────────

// Helmet: sensible default HTTP security headers
try {
  const helmet = require('helmet');
  app.use(helmet({
    contentSecurityPolicy: false,   // UI uses inline canvas JS — set your own CSP in production
    crossOriginEmbedderPolicy: false,
  }));
} catch {
  // helmet is optional; add to package.json to enable
  console.warn('[CipherQ] helmet not installed — HTTP security headers not set. Run: npm install helmet');
}

// Rate limiting on scan/action endpoints. Keyed by tenant (API key) when
// auth has run and set req.tenantId, falling back to IP otherwise — this
// keeps one tenant's scans from eating another tenant's quota when several
// tenants share an egress IP (e.g. behind a corporate NAT), and stops the
// previous per-IP-only limiter from being trivially bypassed by rotating
// source IPs against a single stolen/shared key.
function makeRateLimiter(max, windowMin) {
  try {
    const rateLimit = require('express-rate-limit');
    return rateLimit({
      windowMs: windowMin * 60 * 1000,
      max,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => req.tenantId || req.ip,
      message: { error: `Too many requests — limit is ${max} per ${windowMin} minutes per tenant.` },
    });
  } catch {
    console.warn('[CipherQ] express-rate-limit not installed — rate limiting disabled. Run: npm install express-rate-limit');
    return (_req, _res, next) => next();
  }
}

const scanLimiter   = makeRateLimiter(20, 15);  // 20 scan starts per 15 min
const reportLimiter = makeRateLimiter(10, 15);  // 10 report downloads per 15 min

// ─── API key authentication ──────────────────────────────────────────────────
// Prior to this fix, cipherq.onrender.com had NO authentication at all: any
// internet user could drive active scans (TLS handshakes, port scans, DNS
// zone transfer attempts) against arbitrary third-party domains, with every
// packet originating from — and attributable to — this server's IP. The only
// throttle was a 20-req/15-min-per-IP limiter, trivially bypassed by rotating
// source IPs. Given this application's own documentation devotes a section to
// the legal risk of unauthorised active scanning, running it as an open
// relay was the most urgent item to close.
//
// Minimal viable fix: static API keys configured via environment variable,
// each mapped to a tenant ID. Not a full account/signup system — that's a
// larger product decision (billing, self-serve provisioning, password reset,
// etc.) that shouldn't be invented unilaterally in a bug-fix pass. This gets
// the open-relay problem closed today and gives every tenant's data (CBOM,
// vendor assessments, job results) a namespace to live in; a fuller auth
// system can replace the key-lookup internals later without touching the
// tenant-scoping plumbing built on top of it.
//
// Format: CIPHERQ_API_KEYS="key1:tenant1,key2:tenant2"
//
// Fails CLOSED if unconfigured — matching the same philosophy as the
// Internal Discovery allowlist above. An unauthenticated scanner that can be
// pointed at arbitrary third-party infrastructure is a liability; a scanner
// that refuses to run until a key is issued is an inconvenience. Configure
// CIPHERQ_API_KEYS before deploying, or explicitly set
// CIPHERQ_DISABLE_AUTH=true for local development / trusted-network
// self-hosting only.
const API_KEYS = new Map(
  (process.env.CIPHERQ_API_KEYS || '')
    .split(',')
    .map(pair => pair.trim())
    .filter(Boolean)
    .map(pair => {
      const idx = pair.indexOf(':');
      if (idx < 0) return null;
      return [pair.slice(0, idx).trim(), pair.slice(idx + 1).trim()];
    })
    .filter(Boolean)
);

const AUTH_DISABLED = process.env.CIPHERQ_DISABLE_AUTH === 'true';

if (AUTH_DISABLED) {
  console.warn(
    '[CipherQ] CIPHERQ_DISABLE_AUTH=true — API authentication is OFF. ' +
    'This server will actively scan any target an unauthenticated caller ' +
    'requests. Use only on a trusted network / local development.'
  );
} else if (API_KEYS.size === 0) {
  console.warn(
    '[CipherQ] No CIPHERQ_API_KEYS configured — every scan/report/vendor/' +
    'internal-discovery endpoint will refuse requests (401) until at least ' +
    'one key is set. Set CIPHERQ_API_KEYS="somekey:sometenant" to enable access.'
  );
}

function requireApiKey(req, res, next) {
  if (AUTH_DISABLED) { req.tenantId = 'default'; return next(); }

  const header = req.get('x-cipherq-api-key') ||
    (req.get('authorization') || '').replace(/^Bearer\s+/i, '') || null;

  if (!header) {
    return res.status(401).json({ error: 'Missing API key. Send it as X-CipherQ-Api-Key or Authorization: Bearer <key>.' });
  }
  const tenantId = API_KEYS.get(header);
  if (!tenantId) {
    return res.status(401).json({ error: 'Invalid API key.' });
  }
  req.tenantId = tenantId;
  next();
}

app.use(express.json({ limit: '4mb' }));

// ─── Static files ─────────────────────────────────────────────────────────────

const publicDir = (() => {
  const fs = require('fs');
  for (const name of ['Public', 'public']) {
    const p = path.join(__dirname, name);
    if (fs.existsSync(p)) return p;
  }
  return __dirname;
})();

app.use(express.static(publicDir));
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  const fs = require('fs');
  for (const loc of [
    path.join(publicDir, 'index.html'),
    path.join(__dirname, 'index.html'),
  ]) {
    if (fs.existsSync(loc)) return res.sendFile(loc);
  }
  res.status(404).send('index.html not found');
});

// ─── Domain validation ────────────────────────────────────────────────────────

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function validateDomain(domain, res) {
  if (!domain || typeof domain !== 'string') {
    res.status(400).json({ error: 'domain is required' });
    return false;
  }
  const clean = domain.trim().toLowerCase();
  if (!DOMAIN_RE.test(clean)) {
    res.status(400).json({ error: `Invalid domain format: "${domain}"` });
    return false;
  }
  return true;
}

// ─── In-memory scan job store ─────────────────────────────────────────────────

const jobs = new Map();

function generateJobId(prefix = 'scan') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// Prune completed/errored jobs older than 15 minutes to prevent memory leaks.
// .unref() lets Node exit cleanly without waiting for this timer.
setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  for (const [id, job] of jobs) {
    if (job.status === 'running') continue;
    const ts = new Date(job.completed || job.started || 0).getTime();
    if (ts < cutoff) jobs.delete(id);
  }
}, 60_000).unref();

// ─── POST /api/scan — Start a TLS/PQC scan job ───────────────────────────────

app.post('/api/scan', requireApiKey, scanLimiter, async (req, res) => {
  const { domain, customHosts, deepLegacy = true, weakCipher = true, ctHostsFromBrowser = [] } = req.body;

  if (!validateDomain(domain, res)) return;

  // SSRF guard — refuse scans against private/loopback addresses
  try {
    await assertScannable(domain);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const jobId = generateJobId('scan');
  const job   = {
    id: jobId, domain, status: 'running', tenantId: req.tenantId,
    started: new Date().toISOString(),
    progress: { completed: 0, total: 0 },
    result: null, error: null,
  };
  jobs.set(jobId, job);

  scanDomain(domain, {
    customHosts: customHosts?.length > 0 ? customHosts : ctHostsFromBrowser,
    ctHostsFromBrowser,
    deepLegacyProbe: deepLegacy,
    weakCipherProbe: weakCipher,
    concurrency: 8,
    useCTLog: false,
    onProgress: ({ completed, total }) => {
      job.progress = { completed, total };
    },
  }).then(result => {
    job.status    = 'complete';
    job.completed = new Date().toISOString();
    job.result    = result;
  }).catch(err => {
    job.status = 'error';
    job.error  = err.message;
  });

  res.json({ jobId, status: 'running' });
});

// ─── GET /api/scan/:jobId/stream — SSE progress ───────────────────────────────

app.get('/api/scan/:jobId/stream', requireApiKey, (req, res) => {
  const job = jobs.get(req.params.jobId);
  // 404 (not 403) on tenant mismatch — don't confirm to a caller with a
  // valid-but-wrong key whether a given jobId exists at all.
  if (!job || job.tenantId !== req.tenantId) { res.status(404).end(); return; }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (data) => {
    try { res.write(`data: ${JSON.stringify(data)}\n\n`); } catch {}
  };

  send({ status: job.status, progress: job.progress });

  if (job.status === 'complete') {
    send({ status: 'complete', result: job.result });
    res.end();
    return;
  }

  let lastCompleted = -1;
  const interval = setInterval(() => {
    if (job.status === 'running') {
      const { completed, total } = job.progress || {};
      if (completed !== lastCompleted) {
        lastCompleted = completed;
        send({ status: 'running', progress: job.progress });
      } else {
        try { res.write(': heartbeat\n\n'); } catch {}
      }
    }

    if (job.status === 'complete') {
      clearInterval(interval);
      send({ status: 'complete', result: job.result });
      res.end();
    }

    if (job.status === 'error') {
      clearInterval(interval);
      send({ status: 'error', error: job.error });
      res.end();
    }
  }, 1000);

  req.on('close', () => clearInterval(interval));
});

// ─── GET /api/scan/:jobId — Poll job status ───────────────────────────────────

app.get('/api/scan/:jobId', requireApiKey, (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job || job.tenantId !== req.tenantId) return res.status(404).json({ error: 'Job not found' });

  if (job.status !== 'complete') {
    return res.json({ jobId: job.id, status: job.status, progress: job.progress });
  }
  res.json({ jobId: job.id, status: job.status, result: job.result });
});

// ─── POST /api/analyse — Single host analysis ──────────────────────────────────

app.post('/api/analyse', requireApiKey, async (req, res) => {
  const { hostname, deepLegacy = true, weakCipher = true } = req.body;
  if (!hostname) return res.status(400).json({ error: 'hostname is required' });

  try {
    await assertScannable(hostname);
    const result = await analyseHost(hostname, { deepLegacyProbe: deepLegacy, weakCipherProbe: weakCipher });
    res.json(result);
  } catch (e) {
    res.status(e.message.startsWith('SSRF') ? 400 : 500).json({ error: e.message });
  }
});

// ─── GET /api/hosts/:domain — List candidate subdomains ───────────────────────

app.get('/api/hosts/:domain', async (req, res) => {
  // No requireApiKey: no network I/O, no tenant data — see note above.
  const hosts = await generateSubdomains(req.params.domain);
  res.json({ domain: req.params.domain, hosts, count: hosts.length });
});

// ─── POST /api/dns-scan ────────────────────────────────────────────────────────

app.post('/api/dns-scan', requireApiKey, scanLimiter, async (req, res) => {
  const { domain, hosts = [] } = req.body;
  if (!validateDomain(domain, res)) return;

  try {
    await assertScannable(domain);
    const { scanDNSSecurity } = require('./dns-security');
    const result = await scanDNSSecurity(domain, hosts);
    res.json(result);
  } catch (e) {
    console.error('DNS scan error:', e);
    res.status(e.message.startsWith('SSRF') ? 400 : 500).json({ error: e.message });
  }
});

// ─── POST /api/http-scan ───────────────────────────────────────────────────────

app.post('/api/http-scan', requireApiKey, scanLimiter, async (req, res) => {
  const { domain, hosts = [] } = req.body;
  if (!validateDomain(domain, res)) return;

  try {
    await assertScannable(domain);
    const { scanHTTPSecurity } = require('./http-security');
    const result = await Promise.race([
      scanHTTPSecurity(domain, hosts),
      new Promise((_, r) => setTimeout(() => r(new Error('HTTP scan timed out after 45s')), 45000)),
    ]);
    res.json(result);
  } catch (e) {
    console.error('HTTP scan error:', e.message);
    res.json({
      findings: [], error: e.message,
      summary: { hostsScanned: 0, totalFindings: 0, bySeverity: { critical:0, high:0, medium:0, low:0, info:0 },
                 missingHSTS: 0, missingCSP: 0, corsIssues: 0, cookieIssues: 0,
                 traceEnabled: false, graphqlExposed: false, serverDisclosure: [] },
    });
  }
});

// ─── POST /api/network-scan ────────────────────────────────────────────────────

app.post('/api/network-scan', requireApiKey, scanLimiter, async (req, res) => {
  const { domain, hosts = [] } = req.body;
  if (!validateDomain(domain, res)) return;

  try {
    await assertScannable(domain);
    const { scanNetworkSecurity } = require('./network-security');
    const result = await Promise.race([
      scanNetworkSecurity(domain, hosts),
      new Promise((_, r) => setTimeout(() => r(new Error('Network scan timed out after 90s')), 90000)),
    ]);
    res.json(result);
  } catch (e) {
    console.error('Network scan error:', e.message);
    res.json({
      findings: [], error: e.message,
      summary: { ipsScanned:0, openPortsTotal:0, criticalPorts:0, sshHostsScanned:0,
                 sshPQReady:0, smtpHostsScanned:0, smtpStartTLS:0, totalFindings:0,
                 bySeverity:{critical:0,high:0,medium:0,low:0,info:0} },
      report: { portScans:[], sshScans:[], smtpScans:[], ipv6:[] },
    });
  }
});

// ─── POST /api/report — Generate DOCX report ──────────────────────────────────

app.post('/api/report', requireApiKey, reportLimiter, async (req, res) => {
  const scan        = req.body.scanResult  || req.body;
  const dnsData     = req.body.dnsData     || null;
  const httpData    = req.body.httpData    || null;
  const networkData = req.body.networkData || null;
  const boardMetrics = req.body.boardMetrics || null;
  const codeData    = req.body.codeData    || null;
  const pkiData     = req.body.pkiData     || null;
  const vendorData  = req.body.vendorData  || null;

  if (!scan || !scan.summary) {
    return res.status(400).json({ error: 'Valid scan result required in request body.' });
  }

  try {
    const { generateReport } = require('./report');
    const buffer   = await generateReport(scan, dnsData, httpData, networkData, boardMetrics, codeData, pkiData, vendorData);
    const domain   = scan.summary.domain.replace(/[^a-zA-Z0-9.\-]/g, '_');
    const date     = new Date().toISOString().slice(0, 10);
    const filename = `CipherQ_QTA_${domain}_${date}.docx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (e) {
    console.error('Report generation error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/cbom/persist ───────────────────────────────────────────────────
// Persists a completed scan into the CBOM store and returns the updated store.

app.post('/api/cbom/persist', requireApiKey, async (req, res) => {
  const { domain, scanResult, dnsData, httpData, networkData } = req.body;
  if (!validateDomain(domain, res)) return;
  if (!scanResult?.summary) return res.status(400).json({ error: 'scanResult.summary required' });

  try {
    const store = persistScan(domain, scanResult, dnsData || null, httpData || null, networkData || null, req.tenantId);
    res.json({ ok: true, scanCount: store.scans.length });
  } catch (e) {
    console.error('CBOM persist error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── GET /api/cbom/board-metrics/:domain ──────────────────────────────────────

app.get('/api/cbom/board-metrics/:domain', requireApiKey, (req, res) => {
  const domain = req.params.domain;
  if (!validateDomain(domain, res)) return;

  try {
    // Tenant-scoped (see cbom.js). Previously this returned whichever
    // tenant's stored CBOM matched the domain name to ANY caller — a
    // cross-tenant read with no authorisation check of any kind.
    const metrics = getBoardMetrics(domain, req.tenantId);
    res.json(metrics);
  } catch (e) {
    console.error('CBOM metrics error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── GET /api/vendor — List previously assessed vendors ───────────────────────

app.get('/api/vendor', requireApiKey, (req, res) => {
  try {
    const data = listVendors(req.tenantId);
    res.json(data);
  } catch (e) {
    res.json({ vendors: [] });
  }
});

// ─── POST /api/vendor/assess — Start a vendor assessment job ──────────────────

app.post('/api/vendor/assess', requireApiKey, scanLimiter, async (req, res) => {
  const { vendorName, domain, includeNetworkScan = false } = req.body;

  if (!vendorName || typeof vendorName !== 'string') {
    return res.status(400).json({ error: 'vendorName is required' });
  }
  if (!validateDomain(domain, res)) return;

  try {
    await assertScannable(domain);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const jobId = startVendorAssessment(
    vendorName.trim().slice(0, 200),
    domain.trim().toLowerCase(),
    !!includeNetworkScan,
    req.tenantId
  );
  res.json({ jobId, status: 'running' });
});

// ─── GET /api/vendor/assess/:jobId — Poll vendor job ──────────────────────────

app.get('/api/vendor/assess/:jobId', requireApiKey, (req, res) => {
  const job = getVendorJob(req.params.jobId);
  if (!job || job.tenantId !== req.tenantId) return res.status(404).json({ error: 'Vendor job not found' });

  if (job.status === 'running') {
    return res.json({ status: 'running', progress: job.progress });
  }
  if (job.status === 'error') {
    return res.json({ status: 'error', error: job.error });
  }
  res.json({ status: 'complete', result: job.result });
});

// ─── POST /api/internal/code-scan ─────────────────────────────────────────────
// Scans a local filesystem path for crypto anti-patterns and hardcoded secrets.
// Only reaches paths the server process can read — callers must supply an
// absolute path on the server.

app.post('/api/internal/code-scan', requireApiKey, async (req, res) => {
  const { rootPath, domain = 'internal' } = req.body;

  let validatedPath;
  try {
    validatedPath = validateInternalScanPath(rootPath);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  try {
    const result = await runCodeScan(validatedPath, domain);
    res.json(result);
  } catch (e) {
    console.error('Code scan error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/internal/pki-scan ──────────────────────────────────────────────

app.post('/api/internal/pki-scan', requireApiKey, async (req, res) => {
  const { rootPath, domain = 'internal' } = req.body;

  let validatedPath;
  try {
    validatedPath = validateInternalScanPath(rootPath);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  try {
    const result = await runPKIScan(validatedPath, domain);
    res.json(result);
  } catch (e) {
    console.error('PKI scan error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[CipherQ] API running on http://localhost:${PORT}`);
  console.log(`[CipherQ] SSRF guard: active`);
  console.log(`[CipherQ] Auth: ${AUTH_DISABLED ? 'DISABLED (CIPHERQ_DISABLE_AUTH=true)' : API_KEYS.size + ' API key(s) configured'}`);
  console.log(`[CipherQ] Rate limiting: 20 scans / 15 min per tenant`);
  console.log(`[CipherQ] Internal Discovery roots: ${INTERNAL_SCAN_ALLOWED_ROOTS.length > 0 ? INTERNAL_SCAN_ALLOWED_ROOTS.join(', ') : '(none configured — feature disabled)'}`);
  console.log(`[CipherQ] Job TTL cleanup: every 60 s (15 min TTL)`);
});

module.exports = app;
