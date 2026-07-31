'use strict';

/**
 * CipherQ PQC Scanner — API Server  (v2.1.1)
 *
 * Changes from v2.1:
 *   • SSE heartbeat changed from a comment (': heartbeat') to a real data event
 *     so browser onmessage fires and resets the client-side watchdog — fixes the
 *     spurious "No progress for 60s" stall error on slow scans.
 *   • GET /api/client-config added (unauthenticated) — returns
 *     CIPHERQ_FRONTEND_API_KEY env var for forward-compatible frontend auth.
 */

const express = require('express');
const path    = require('path');
const https   = require('https');

const { scanDomain, analyseHost, generateSubdomains } = require('./scanner');
const { assertScannable } = require('./ssrf-guard');
const { persistScan, getBoardMetrics, listVendors }   = require('./cbom');
const { startVendorAssessment, getVendorJob }         = require('./vendor');
const { runCodeScan, runPKIScan }                     = require('./internal-scanner');

const app = express();

// ─── Security middleware ──────────────────────────────────────────────────────

try {
  const helmet = require('helmet');
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }));
} catch {
  console.warn('[CipherQ] helmet not installed — HTTP security headers not set. Run: npm install helmet');
}

function makeRateLimiter(max, windowMin) {
  try {
    const rateLimit = require('express-rate-limit');
    return rateLimit({
      windowMs: windowMin * 60 * 1000,
      max,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: `Too many requests — limit is ${max} per ${windowMin} minutes per IP.` },
    });
  } catch {
    console.warn('[CipherQ] express-rate-limit not installed — rate limiting disabled. Run: npm install express-rate-limit');
    return (_req, _res, next) => next();
  }
}

const scanLimiter   = makeRateLimiter(20, 15);
const reportLimiter = makeRateLimiter(10, 15);

app.use(express.json({ limit: '4mb' }));

// ─── GET /api/client-config — public; no auth required ───────────────────────
// Returns CIPHERQ_FRONTEND_API_KEY so the frontend can self-configure.
// Set this env var in Render if you add server-side auth in future.
app.get('/api/client-config', (req, res) => {
  res.json({ apiKey: process.env.CIPHERQ_FRONTEND_API_KEY || '' });
});

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

setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  for (const [id, job] of jobs) {
    if (job.status === 'running') continue;
    const ts = new Date(job.completed || job.started || 0).getTime();
    if (ts < cutoff) jobs.delete(id);
  }
}, 60_000).unref();

// ─── POST /api/scan ───────────────────────────────────────────────────────────

app.post('/api/scan', scanLimiter, async (req, res) => {
  const { domain, customHosts, deepLegacy = true, weakCipher = true, ctHostsFromBrowser = [] } = req.body;

  if (!validateDomain(domain, res)) return;

  try {
    await assertScannable(domain);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const jobId = generateJobId('scan');
  const job   = {
    id: jobId, domain, status: 'running',
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

app.get('/api/scan/:jobId/stream', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) { res.status(404).end(); return; }

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
        // Real data event (not a comment) so browser onmessage fires and
        // resets the client-side watchdog timer. The frontend ignores type=heartbeat.
        try { res.write('data: {"type":"heartbeat"}\n\n'); } catch {}
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

// ─── GET /api/scan/:jobId ─────────────────────────────────────────────────────

app.get('/api/scan/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  if (job.status !== 'complete') {
    return res.json({ jobId: job.id, status: job.status, progress: job.progress });
  }
  res.json({ jobId: job.id, status: job.status, result: job.result });
});

// ─── POST /api/analyse ────────────────────────────────────────────────────────

app.post('/api/analyse', async (req, res) => {
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

// ─── GET /api/hosts/:domain ───────────────────────────────────────────────────

app.get('/api/hosts/:domain', async (req, res) => {
  const hosts = await generateSubdomains(req.params.domain);
  res.json({ domain: req.params.domain, hosts, count: hosts.length });
});

// ─── POST /api/dns-scan ───────────────────────────────────────────────────────

app.post('/api/dns-scan', scanLimiter, async (req, res) => {
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

// ─── POST /api/http-scan ──────────────────────────────────────────────────────

app.post('/api/http-scan', scanLimiter, async (req, res) => {
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

// ─── POST /api/network-scan ───────────────────────────────────────────────────

app.post('/api/network-scan', scanLimiter, async (req, res) => {
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

// ─── POST /api/report ─────────────────────────────────────────────────────────

app.post('/api/report', reportLimiter, async (req, res) => {
  const scan         = req.body.scanResult  || req.body;
  const dnsData      = req.body.dnsData     || null;
  const httpData     = req.body.httpData    || null;
  const networkData  = req.body.networkData || null;
  const boardMetrics = req.body.boardMetrics || null;
  const codeData     = req.body.codeData    || null;
  const pkiData      = req.body.pkiData     || null;
  const vendorData   = req.body.vendorData  || null;

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

app.post('/api/cbom/persist', async (req, res) => {
  const { domain, scanResult, dnsData, httpData, networkData } = req.body;
  if (!validateDomain(domain, res)) return;
  if (!scanResult?.summary) return res.status(400).json({ error: 'scanResult.summary required' });

  try {
    const store = persistScan(domain, scanResult, dnsData || null, httpData || null, networkData || null);
    res.json({ ok: true, scanCount: store.scans.length });
  } catch (e) {
    console.error('CBOM persist error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── GET /api/cbom/board-metrics/:domain ──────────────────────────────────────

app.get('/api/cbom/board-metrics/:domain', (req, res) => {
  const domain = req.params.domain;
  if (!validateDomain(domain, res)) return;

  try {
    const metrics = getBoardMetrics(domain);
    res.json(metrics);
  } catch (e) {
    console.error('CBOM metrics error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── GET /api/vendor ──────────────────────────────────────────────────────────

app.get('/api/vendor', (req, res) => {
  try {
    const data = listVendors();
    res.json(data);
  } catch (e) {
    res.json({ vendors: [] });
  }
});

// ─── POST /api/vendor/assess ──────────────────────────────────────────────────

app.post('/api/vendor/assess', scanLimiter, async (req, res) => {
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
    !!includeNetworkScan
  );
  res.json({ jobId, status: 'running' });
});

// ─── GET /api/vendor/assess/:jobId ───────────────────────────────────────────

app.get('/api/vendor/assess/:jobId', (req, res) => {
  const job = getVendorJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Vendor job not found' });

  if (job.status === 'running') {
    return res.json({ status: 'running', progress: job.progress });
  }
  if (job.status === 'error') {
    return res.json({ status: 'error', error: job.error });
  }
  res.json({ status: 'complete', result: job.result });
});

// ─── POST /api/internal/code-scan ────────────────────────────────────────────

app.post('/api/internal/code-scan', async (req, res) => {
  const { rootPath, domain = 'internal' } = req.body;

  if (!rootPath || typeof rootPath !== 'string') {
    return res.status(400).json({ error: 'rootPath is required' });
  }

  const normalized = require('path').resolve(rootPath);
  const forbidden  = ['/proc', '/sys', '/dev', '/etc/shadow', '/etc/passwd'];
  if (forbidden.some(p => normalized.startsWith(p))) {
    return res.status(400).json({ error: `Refused: rootPath "${normalized}" is a restricted system path` });
  }

  try {
    const result = await runCodeScan(normalized, domain);
    res.json(result);
  } catch (e) {
    console.error('Code scan error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/internal/pki-scan ─────────────────────────────────────────────

app.post('/api/internal/pki-scan', async (req, res) => {
  const { rootPath, domain = 'internal' } = req.body;

  if (!rootPath || typeof rootPath !== 'string') {
    return res.status(400).json({ error: 'rootPath is required' });
  }

  const normalized = require('path').resolve(rootPath);
  const forbidden  = ['/proc', '/sys', '/dev'];
  if (forbidden.some(p => normalized.startsWith(p))) {
    return res.status(400).json({ error: `Refused: rootPath "${normalized}" is a restricted system path` });
  }

  try {
    const result = await runPKIScan(normalized, domain);
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
  console.log(`[CipherQ] Rate limiting: 20 scans / 15 min per IP`);
  console.log(`[CipherQ] Job TTL cleanup: every 60 s (15 min TTL)`);
});

module.exports = app;
