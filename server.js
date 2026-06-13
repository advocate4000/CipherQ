'use strict';

/**
 * PQC Scanner — API Server
 * Provides a REST API and serves the web UI
 */

const express = require('express');
const path = require('path');
const https = require('https');
const { scanDomain, analyseHost, generateSubdomains } = require('./scanner');

const app = express();
app.use(express.json({ limit: '2mb' }));

// Serve from both 'Public' (capital P, as uploaded) and 'public' (lowercase)
const publicDir = (() => {
  const fs = require('fs');
  for (const name of ['Public', 'public']) {
    const p = path.join(__dirname, name);
    if (fs.existsSync(p)) return p;
  }
  return __dirname; // fallback: serve from root
})();

app.use(express.static(publicDir));
app.use(express.static(__dirname)); // also serve root-level index.html as fallback

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

// ─── POST /api/ai-scan — Anthropic API proxy ─────────────────────────────────
// Keeps the API key server-side; browser calls this instead of api.anthropic.com
app.post('/api/ai-scan', (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY environment variable not set on server.' });
  }

  const body = JSON.stringify(req.body);

  const options = {
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'Content-Length': Buffer.byteLength(body),
    },
  };

  const proxyReq = https.request(options, (proxyRes) => {
    let data = '';
    proxyRes.on('data', chunk => data += chunk);
    proxyRes.on('end', () => {
      try {
        res.status(proxyRes.statusCode).json(JSON.parse(data));
      } catch (e) {
        res.status(500).json({ error: 'Invalid response from Anthropic API', raw: data.slice(0, 200) });
      }
    });
  });

  proxyReq.on('error', e => res.status(500).json({ error: e.message }));
  proxyReq.write(body);
  proxyReq.end();
});

// In-memory scan job store (production: use Redis/DB)
const jobs = new Map();

function generateJobId() {
  return `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ─── POST /api/scan — Start a scan job ───────────────────────────────────────
app.post('/api/scan', async (req, res) => {
  const { domain, customHosts, deepLegacy = true, weakCipher = true } = req.body;

  if (!domain) return res.status(400).json({ error: 'domain is required' });

  // Basic validation
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  const jobId = generateJobId();
  const job = {
    id: jobId,
    domain,
    status: 'running',
    started: new Date().toISOString(),
    progress: { completed: 0, total: 0 },
    result: null,
    error: null,
  };
  jobs.set(jobId, job);

  // Run scan asynchronously
  scanDomain(domain, {
    customHosts: customHosts || [],
    deepLegacyProbe: deepLegacy,
    weakCipherProbe: weakCipher,
    concurrency: 8,
    useCTLog: true,
    onProgress: ({ phase, completed, total, message, latest }) => {
      if (phase === 'ct-discovery') {
        job.progress = { phase: 'ct-discovery', message: message || 'Querying Certificate Transparency logs…' };
      } else {
        job.progress = { completed, total };
      }
    },
  }).then(result => {
    job.status = 'complete';
    job.completed = new Date().toISOString();
    job.result = result;
  }).catch(err => {
    job.status = 'error';
    job.error = err.message;
  });

  res.json({ jobId, status: 'running' });
});

// ─── GET /api/scan/:jobId — Poll job status ───────────────────────────────────
app.get('/api/scan/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  if (job.status !== 'complete') {
    return res.json({ jobId: job.id, status: job.status, progress: job.progress });
  }

  res.json({ jobId: job.id, status: job.status, result: job.result });
});

// ─── POST /api/analyse — Single host analysis ──────────────────────────────────
app.post('/api/analyse', async (req, res) => {
  const { hostname, deepLegacy = true, weakCipher = true } = req.body;
  if (!hostname) return res.status(400).json({ error: 'hostname is required' });

  try {
    const result = await analyseHost(hostname, {
      deepLegacyProbe: deepLegacy,
      weakCipherProbe: weakCipher,
    });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── GET /api/hosts/:domain — List default probed subdomains ──────────────────
app.get('/api/hosts/:domain', async (req, res) => {
  const hosts = await generateSubdomains(req.params.domain);
  res.json({ domain: req.params.domain, hosts, count: hosts.length });
});

// ─── POST /api/dns-scan — DNS vulnerability scan ──────────────────────────────
app.post('/api/dns-scan', async (req, res) => {
  const { domain, hosts = [] } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain is required' });

  try {
    const { scanDNSSecurity } = require('./dns-security');
    const result = await scanDNSSecurity(domain, hosts);
    res.json(result);
  } catch (e) {
    console.error('DNS scan error:', e);
    res.status(500).json({ error: e.message });
  }
});
app.post('/api/report', async (req, res) => {
  const scanResult = req.body;
  if (!scanResult || !scanResult.summary) {
    return res.status(400).json({ error: 'Valid scan result required in request body.' });
  }

  try {
    const { generateReport } = require('./report');
    const buffer = await generateReport(scanResult);
    const domain = scanResult.summary.domain.replace(/[^a-zA-Z0-9.-]/g, '_');
    const date = new Date().toISOString().slice(0, 10);
    const filename = `CipherQ_QTA_${domain}_${date}.docx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (e) {
    console.error('Report generation error:', e);
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`PQC Scanner API running on http://localhost:${PORT}`);
});

module.exports = app;
