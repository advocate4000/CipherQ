'use strict';

/**
 * PQC Scanner — API Server
 * Provides a REST API and serves the web UI
 */

const express = require('express');
const path = require('path');
const { scanDomain, analyseHost, generateSubdomains } = require('./scanner');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
    concurrency: 5,
    onProgress: ({ completed, total, latest }) => {
      job.progress = { completed, total };
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`PQC Scanner API running on http://localhost:${PORT}`);
});

module.exports = app;
