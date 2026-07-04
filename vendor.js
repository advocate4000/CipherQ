'use strict';

/**
 * CipherQ — Vendor Security Scorecard
 *
 * Runs a full TLS + DNS + HTTP assessment against a vendor domain and
 * computes a scored, graded report card across five categories.
 * Orchestrated via a job store so the UI can poll for progress.
 */

const { scanDomain }       = require('./scanner');
const { scanDNSSecurity }  = require('./dns-security');
const { scanHTTPSecurity } = require('./http-security');
const { scanNetworkSecurity } = require('./network-security');
const { assertScannable }  = require('./ssrf-guard');
const { upsertVendor }     = require('./cbom');

// ─── In-memory job store (same pattern as main scan jobs) ────────────────────
const vendorJobs = new Map();

// Prune completed jobs after 30 min
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  for (const [id, job] of vendorJobs) {
    if (job.status !== 'running' && new Date(job.started).getTime() < cutoff) {
      vendorJobs.delete(id);
    }
  }
}, 60_000).unref();

function generateJobId() {
  return `vendor_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/**
 * Score 0–100 across five categories.
 * Higher = better posture (inverse of QEI).
 */
function scoreVendor(scanResult, dnsData, httpData, networkData) {
  const { summary, hosts } = scanResult;
  const reachable = hosts.filter(h => h.tls?.cipher);
  const ds = dnsData?.report?.summary  || {};
  const hs = httpData?.summary         || {};
  const ns = networkData?.summary      || {};

  // ── Category 1: PQ / TLS Readiness (0–25) ────────────────────────────────
  let pqScore = 25;
  const totalHosts = reachable.length || 1;
  const pqReady   = (summary.pqReadinessBreakdown?.ready   || 0);
  const pqNone    = (summary.pqReadinessBreakdown?.none    || 0);
  const pqUnknown = (summary.pqReadinessBreakdown?.unknown || 0);

  pqScore -= Math.round((pqNone    / totalHosts) * 18);
  pqScore -= Math.round((pqUnknown / totalHosts) * 10);
  pqScore += Math.round((pqReady   / totalHosts) * 8);

  const hasCritTLS = scanResult.findings.some(
    f => f.severity === 'critical' && f.area?.startsWith('tls')
  );
  if (hasCritTLS) pqScore -= 8;
  pqScore = Math.max(0, Math.min(25, pqScore));

  // ── Category 2: Email Security (0–20) ─────────────────────────────────────
  let emailScore = 20;
  if (!ds.spfPresent)                  emailScore -= 8;
  if (!ds.dmarcPolicy || ds.dmarcPolicy === 'missing') emailScore -= 8;
  else if (ds.dmarcPolicy === 'none')  emailScore -= 5;
  else if (ds.dmarcPolicy === 'quarantine') emailScore -= 2;
  if (dnsData?.findings?.some(f => f.id === 'EMAIL-SPF-PLUS-ALL'))  emailScore -= 6;
  if (!dnsData) emailScore = 10; // not tested — partial credit
  emailScore = Math.max(0, Math.min(20, emailScore));

  // ── Category 3: Web Security / HTTP Headers (0–20) ────────────────────────
  let webScore = 20;
  if (hs.missingHSTS > 0) webScore -= 6;
  if (hs.missingCSP  > 0) webScore -= 5;
  if (hs.corsIssues  > 0) webScore -= 5;
  if (hs.cookieIssues > 0) webScore -= 2;
  if (hs.graphqlExposed)  webScore -= 3;
  if (!httpData) webScore = 12; // not tested
  webScore = Math.max(0, Math.min(20, webScore));

  // ── Category 4: Network Exposure (0–20) ───────────────────────────────────
  let netScore = 20;
  if (ns.criticalPorts > 0)     netScore -= Math.min(15, ns.criticalPorts * 5);
  if (ds.axfrVulnerable)        netScore -= 8;
  if (ds.takeoverCount > 0)     netScore -= 6;
  if (ds.openResolverCount > 0) netScore -= 4;
  if (!networkData) netScore = 12;
  netScore = Math.max(0, Math.min(20, netScore));

  // ── Category 5: Certificate Hygiene (0–15) ────────────────────────────────
  let certScore = 15;
  const sniMismatches = summary.sniMismatches?.length || 0;
  if (sniMismatches > 0)  certScore -= 5;
  const expiredCerts = scanResult.findings.filter(f => f.id === 'CERT-EXPIRED').length;
  const expiringSoon = scanResult.findings.filter(f => f.id === 'CERT-EXPIRY-CRITICAL').length;
  if (expiredCerts  > 0)  certScore -= 8;
  if (expiringSoon  > 0)  certScore -= 4;
  if (!ds.caaPresent && dnsData) certScore -= 2;
  certScore = Math.max(0, Math.min(15, certScore));

  const overall = pqScore + emailScore + webScore + netScore + certScore;

  function grade(s, max) {
    const pct = s / max;
    if (pct >= 0.9) return 'A';
    if (pct >= 0.75) return 'B';
    if (pct >= 0.6)  return 'C';
    if (pct >= 0.45) return 'D';
    return 'F';
  }

  return {
    overallScore: overall,
    grade: grade(overall, 100),
    categoryScores: {
      pqReadiness:    pqScore,
      emailSecurity:  emailScore,
      webSecurity:    webScore,
      networkExposure: netScore,
      certHygiene:    certScore,
    },
    categoryGrades: {
      pqReadiness:    grade(pqScore, 25),
      emailSecurity:  grade(emailScore, 20),
      webSecurity:    grade(webScore, 20),
      networkExposure: grade(netScore, 20),
      certHygiene:    grade(certScore, 15),
    },
    topConcerns: [
      ...scanResult.findings.filter(f => f.severity === 'critical' || f.severity === 'high'),
      ...(dnsData?.findings     || []).filter(f => f.severity === 'critical' || f.severity === 'high'),
      ...(httpData?.findings    || []).filter(f => f.severity === 'critical' || f.severity === 'high'),
      ...(networkData?.findings || []).filter(f => f.severity === 'critical' || f.severity === 'high'),
    ].slice(0, 10),
  };
}

// ─── Assessment runner ────────────────────────────────────────────────────────

async function runAssessment(job) {
  const { vendorName, domain, includeNetworkScan } = job;

  const progress = (msg) => { job.progress = { message: msg }; };

  try {
    // SSRF check — vendor must resolve to a public IP
    progress('Validating domain…');
    await assertScannable(domain);

    // TLS scan
    progress('Running TLS / PQC scan…');
    const scanResult = await scanDomain(domain, {
      concurrency: 8,
      deepLegacyProbe: true,
      weakCipherProbe: true,
    });

    // DNS
    progress('Running DNS security checks…');
    const dnsData = await scanDNSSecurity(
      domain,
      scanResult.hosts.filter(h => h.dns?.resolves)
    ).catch(e => ({ findings: [], report: { summary: {} }, error: e.message }));

    // HTTP
    progress('Scanning HTTP security headers…');
    const httpData = await Promise.race([
      scanHTTPSecurity(domain, scanResult.hosts.filter(h => h.tls?.cipher)),
      new Promise((_, r) => setTimeout(() => r(new Error('HTTP scan timed out')), 45000)),
    ]).catch(e => ({ findings: [], summary: {}, error: e.message }));

    // Network (optional — slower)
    let networkData = null;
    if (includeNetworkScan) {
      progress('Running port / network scan…');
      networkData = await Promise.race([
        scanNetworkSecurity(domain, scanResult.hosts.filter(h => h.dns?.resolves)),
        new Promise((_, r) => setTimeout(() => r(new Error('Network scan timed out')), 90000)),
      ]).catch(e => ({ findings: [], summary: {}, report: {}, error: e.message }));
    }

    progress('Computing vendor scorecard…');
    const scorecard = scoreVendor(scanResult, dnsData, httpData, networkData);

    const result = {
      vendor: { name: vendorName, domain, assessedAt: new Date().toISOString() },
      scanResult,
      dnsData,
      httpData,
      networkData,
      scorecard,
    };

    // Persist to vendor CBOM
    upsertVendor({
      name:           vendorName,
      domain,
      grade:          scorecard.grade,
      overallScore:   scorecard.overallScore,
      categoryScores: scorecard.categoryScores,
      lastAssessedAt: result.vendor.assessedAt,
    });

    job.status = 'complete';
    job.result = result;

  } catch (err) {
    job.status = 'error';
    job.error  = err.message;
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

function startVendorAssessment(vendorName, domain, includeNetworkScan = false) {
  const jobId = generateJobId();
  const job = {
    id:       jobId,
    vendorName,
    domain,
    includeNetworkScan,
    status:   'running',
    started:  new Date().toISOString(),
    progress: { message: 'Starting…' },
    result:   null,
    error:    null,
  };
  vendorJobs.set(jobId, job);
  // Fire and forget — caller polls via getJob
  runAssessment(job).catch(() => {});
  return jobId;
}

function getVendorJob(jobId) {
  return vendorJobs.get(jobId) || null;
}

module.exports = { startVendorAssessment, getVendorJob };
