'use strict';

/**
 * CipherQ — CBOM Persistence & Board Metrics
 *
 * Provides:
 *   persistScan(domain, scanResult, dnsData, httpData, networkData)
 *   getBoardMetrics(domain)  → metrics object the UI CBOM Dashboard expects
 *
 * Storage: single JSON file per domain under <DATA_DIR>/<domain>.json
 * Compatible with Render's ephemeral filesystem (survives restarts within the
 * same instance but resets on deploy — production would swap this for a DB).
 * Uses atomic write (write-to-tmp then rename) to avoid torn files.
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const DATA_DIR = process.env.CBOM_DATA_DIR || path.join(os.tmpdir(), 'cipherq-cbom');

// Ensure the data directory exists at startup
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

// Every store is namespaced under a tenant directory. Before this fix,
// storage was keyed purely by domain name — GET /api/cbom/board-metrics/:domain
// returned whichever tenant's data was on disk for that domain to ANY caller,
// with no authorisation check at all (a cross-tenant read). 'default' is used
// when no tenant context is available (e.g. the CLI, or a single-tenant
// self-hosted deployment where the API-key auth middleware is not enabled) so
// existing single-tenant usage keeps working unchanged.
const DEFAULT_TENANT = 'default';

function safeSegment(s) {
  // Strip anything that isn't alphanumeric, dot, or hyphen — used for both
  // the tenant segment and the domain segment, and rejects path traversal
  // sequences (a segment of ".." becomes "__" rather than escaping DATA_DIR).
  return String(s).replace(/[^a-zA-Z0-9.\-]/g, '_').toLowerCase();
}

function tenantDir(tenantId) {
  const dir = path.join(DATA_DIR, safeSegment(tenantId || DEFAULT_TENANT));
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  return dir;
}

function safeFilename(domain) {
  return safeSegment(domain) + '.json';
}

function readDomainStore(domain, tenantId = DEFAULT_TENANT) {
  const p = path.join(tenantDir(tenantId), safeFilename(domain));
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return { domain, tenantId, scans: [], vendors: [], findings: [], waivers: [] };
  }
}

function writeDomainStore(domain, data, tenantId = DEFAULT_TENANT) {
  const p    = path.join(tenantDir(tenantId), safeFilename(domain));
  const tmp  = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

// ─── Severity scoring weights ─────────────────────────────────────────────────

const SEV_WEIGHT = { critical: 25, high: 15, medium: 5, low: 1, info: 0 };

// QEI methodology version. Bump this whenever computeQEI's weights or inputs
// change, so a QEI of "42" on an old scan and a QEI of "42" on a new one can
// be told apart rather than silently compared as if they meant the same
// thing. Stored alongside every persisted scan record and surfaced in
// getBoardMetrics.
const QEI_METHOD_VERSION = 2;   // 1 was the retired in-house scorer

function scoreSeverity(findings = []) {
  return findings.reduce((acc, f) => acc + (SEV_WEIGHT[f.severity] || 0), 0);
}

function countBySev(findings = []) {
  return {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
    info:     findings.filter(f => f.severity === 'info').length,
  };
}

// ─── Quantum Exposure Index ───────────────────────────────────────────────────
// 0 = perfect PQ posture; 100 = maximum exposure.
//
// The methodology lives in qei.js and is shared with the QEA report generator.
// It used to live here, weighted KEX 0-50, an HNDL label 0-20, critical TLS
// findings 0-15, dev hosts 0-10, DNS -10 and SSH 0-5. Both that score and the
// report's were called a QEI and both ran 0-100, so a dashboard reading 61 and
// a delivered report reading 74 could describe the same estate on the same day.
//
// The report's methodology won because it has a data-lifetime dimension —
// retention against the CRQC estimate is the argument the report makes, and a
// score blind to it cannot distinguish a 15-year firm from a 2-year one with
// identical infrastructure — and because every dimension decomposes into
// points, a maximum, and the observation behind it.
//
// Retention is client-attested and often unset, in which case the data-lifetime
// dimension is marked unassessed and dropped from the denominator: the result
// is 58 out of 80, never 58 presented as if out of 100.

const { computeQEI: scoreQEI } = require('./qei');
const { deriveFacts } = require('./qea-input');
const reportProfile = require('./report-profile');

function computeQEI(scanResult, dnsData, httpData, networkData, retentionYears = null) {
  /* networkData was accepted and then ignored. With DNEL in the index it
     carries the operator-surface evidence, so a dashboard computed without
     it would disagree with a report computed with it — the exact split this
     file's header describes closing. deriveFacts now takes it. */
  const f = deriveFacts(scanResult, httpData, networkData);
  return scoreQEI({
    reachable: f.reachable,
    hostsWithPqKex: f.pqHosts,
    hostsTls13: f.reachableHosts.filter(h => h.tls.protocol === 'TLSv1.3').length,
    certsExpiring90d: f.expiring90,
    sniMismatches: f.mismatches,
    allCertsPq: f.reachable > 0 && f.pqSigCount === f.reachable,
    hostsNoHsts: f.noHsts === null ? 0 : f.noHsts,
    hostsNoCsp: f.noCsp === null ? 0 : f.noCsp,
    mixedContentHosts: f.mixed === null ? 0 : f.mixed,
    hostsBelowTls13: f.belowTls13,
    devOrStagingReachable: f.devHosts,
    dormantDnsRecords: f.dormant,
    dnel: f.dnel && f.dnel.facts,
  }, {
    retentionYears,
    assessmentYear: new Date().getFullYear(),
    crqcYear: 2033,
  });
}

// ─── Public: persistScan ──────────────────────────────────────────────────────

function persistScan(domain, scanResult, dnsData = null, httpData = null, networkData = null, tenantId = DEFAULT_TENANT) {
  const store = readDomainStore(domain, tenantId);

  // Aggregate all findings for this scan
  const allFindings = [
    ...(scanResult.findings           || []),
    ...(dnsData?.findings             || []),
    ...(httpData?.findings            || []),
    ...(networkData?.findings         || []),
  ];

  // Compute QEI exactly once, here, from the full scan data (hosts array,
  // raw findings, dns/http/network reports) while we still have all of it.
  // getBoardMetrics() used to re-derive its OWN separate approximation from
  // just the stored summary fields, using different weights entirely
  // (criticalTLS * 3 vs computeQEI's * 5, and no DNS/SSH terms at all) —
  // meaning the CBOM Dashboard and the downloaded report could disagree
  // about the headline number. Storing that one computed value here and
  // having getBoardMetrics simply read it back closes that gap.
  // Retention comes from the client's report profile when one exists. Without
  // it the data-lifetime dimension is unassessed and qeiMax is 80, which the
  // dashboard must show rather than rounding up to an implied 100.
  const retention = reportProfile.retentionYears(domain, tenantId);
  const scored = computeQEI(scanResult, dnsData, httpData, networkData, retention);
  const qei = scored.qei;

  const scanRecord = {
    id:          `scan_${Date.now()}`,
    timestamp:   new Date().toISOString(),
    summary:     scanResult.summary,
    findingsBySeverity: countBySev(allFindings),
    totalFindings: allFindings.length,
    hostsReachable: scanResult.summary.hostsReachable,
    hostsProbed:    scanResult.summary.hostsProbed,
    pqReadinessBreakdown: scanResult.summary.pqReadinessBreakdown,
    overallHndlRisk: scanResult.summary.overallHndlRisk,
    qei,
    qeiMax: scored.qeiMax,
    qeiComplete: scored.complete,
    qeiComponents: scored.components,
    qeiMethodVersion: QEI_METHOD_VERSION,
  };

  store.scans.push(scanRecord);

  // Keep the last 25 scans per domain
  if (store.scans.length > 25) store.scans = store.scans.slice(-25);

  // Merge findings into the CBOM (de-duplicate by id+hostname)
  const existingKeys = new Set(store.findings.map(f => `${f.id}::${f.hostname || ''}`));
  for (const f of allFindings) {
    const key = `${f.id}::${f.hostname || ''}`;
    if (!existingKeys.has(key)) {
      store.findings.push({ ...f, firstSeen: new Date().toISOString(), status: 'open' });
      existingKeys.add(key);
    } else {
      // Update lastSeen on existing finding
      const existing = store.findings.find(x => `${x.id}::${x.hostname || ''}` === key);
      if (existing) existing.lastSeen = new Date().toISOString();
    }
  }

  // Mark findings not seen in this scan as potentially resolved
  const currentKeys = new Set(allFindings.map(f => `${f.id}::${f.hostname || ''}`));
  for (const f of store.findings) {
    if (f.status === 'open') {
      const key = `${f.id}::${f.hostname || ''}`;
      if (!currentKeys.has(key)) {
        f.status = 'possibly-resolved';
        f.resolvedAt = new Date().toISOString();
      }
    }
  }

  writeDomainStore(domain, store, tenantId);
  return store;
}

// ─── Public: getBoardMetrics ──────────────────────────────────────────────────

function getBoardMetrics(domain, tenantId = DEFAULT_TENANT) {
  const store = readDomainStore(domain, tenantId);

  if (store.scans.length === 0) {
    // Return a zero-state rather than an error
    return {
      domain,
      lastScanAt: null,
      quantumExposureIndex: null,
      quantumExposureMax: null,
      quantumExposureComplete: false,
      quantumExposureTrend: null,
      quantumExposureTrendSuppressed: null,
      assetInventory: { total: 0, pqNone: 0, pqUnknown: 0, pqPartial: 0, pqReady: 0, pqReadyPercent: 0 },
      findingsOpen: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      cryptographicDebt: { openFindings: 0, estimatedEffortDays: 0 },
      riskRegister: { activeWaivers: 0, upcomingReviews30d: 0 },
    };
  }

  const latestScan = store.scans[store.scans.length - 1];
  const prevScan   = store.scans.length > 1 ? store.scans[store.scans.length - 2] : null;

  // Read the QEI computed once by persistScan() from the full scan data,
  // rather than re-deriving a second, differently-weighted approximation
  // from just the stored summary fields (the previous version of this
  // function did — see git history / CipherQ_Feature_Review.md F16 for what
  // that let the CBOM Dashboard and the downloaded report disagree about).
  // Older scan records persisted before this fix won't have a `qei` field;
  // fall back to a one-time best-effort estimate for those only, clearly
  // marked as such via qeiMethodVersion so the discrepancy is visible rather
  // than silently blended in with properly-computed values.
  const hasStoredQEI = typeof latestScan.qei === 'number';
  const qei = hasStoredQEI ? latestScan.qei : estimateLegacyQEI(latestScan);
  const qeiMethodVersion = hasStoredQEI ? (latestScan.qeiMethodVersion || 0) : 0;
  const qeiMax = latestScan.qeiMax || 100;
  const qeiComplete = latestScan.qeiComplete !== false;

  // A trend is only meaningful between two scores computed under the same
  // rules and against the same denominator. Subtracting a 58-of-80 from a
  // 74-of-100, or a v1 index from a v2 one, produces a number that looks like
  // progress and means nothing.
  let qeiTrend = null;
  let qeiTrendSuppressed = null;
  if (prevScan) {
    const prevHasStored = typeof prevScan.qei === 'number';
    const prevVersion = prevHasStored ? prevScan.qeiMethodVersion : 0;
    const prevMax = prevScan.qeiMax || 100;
    if (prevVersion !== qeiMethodVersion) {
      qeiTrendSuppressed = `previous scan scored under methodology v${prevVersion}, this one under v${qeiMethodVersion}`;
    } else if (prevMax !== qeiMax) {
      qeiTrendSuppressed = `previous scan scored out of ${prevMax}, this one out of ${qeiMax}`;
    } else {
      qeiTrend = qei - prevScan.qei;
    }
  }

  // Asset inventory breakdown — independent of QEI, still needs the stored
  // PQ readiness breakdown and reachable-host total.
  const pb = latestScan.pqReadinessBreakdown || {};
  const total = latestScan.hostsReachable || 1;

  const openFindings = store.findings.filter(f => f.status === 'open');
  const openBySev    = countBySev(openFindings);

  // Effort estimate: P1=1d, high=0.5d, medium=0.25d, low=0.1d per finding
  const effortDays = Math.ceil(
    openBySev.critical * 1.0 +
    openBySev.high     * 0.5 +
    openBySev.medium   * 0.25 +
    openBySev.low      * 0.1
  );

  const now = new Date();
  const in30 = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  const upcomingReviews = store.waivers.filter(w => {
    if (!w.reviewDate) return false;
    const rd = new Date(w.reviewDate);
    return rd >= now && rd <= in30;
  }).length;

  return {
    domain,
    lastScanAt: latestScan.timestamp,
    totalScans: store.scans.length,
    quantumExposureIndex: qei,
    quantumExposureMax: qeiMax,          // 80 when retention is unknown, 100 when supplied
    quantumExposureComplete: qeiComplete,
    quantumExposureTrend: qeiTrend,
    quantumExposureTrendSuppressed: qeiTrendSuppressed,
    qeiMethodVersion, // 0 = legacy pre-consolidation estimate; see estimateLegacyQEI
    assetInventory: {
      total:          latestScan.hostsProbed    || 0,
      pqNone:         pb.none    || 0,
      pqUnknown:      pb.unknown || 0,
      pqPartial:      pb.partial || 0,
      pqReady:        pb.ready   || 0,
      pqReadyPercent: total > 0 ? Math.round((pb.ready || 0) / total * 100) : 0,
    },
    findingsOpen: openBySev,
    cryptographicDebt: {
      openFindings:         openFindings.length,
      estimatedEffortDays:  effortDays,
    },
    riskRegister: {
      activeWaivers:      store.waivers.filter(w => w.status === 'active').length,
      upcomingReviews30d: upcomingReviews,
    },
  };
}

// ─── Vendor CBOM helpers ──────────────────────────────────────────────────────

function listVendors(tenantId = DEFAULT_TENANT) {
  try {
    const vendorFile = path.join(tenantDir(tenantId), '_vendors.json');
    return JSON.parse(fs.readFileSync(vendorFile, 'utf8'));
  } catch {
    return { vendors: [] };
  }
}

function upsertVendor(vendorRecord, tenantId = DEFAULT_TENANT) {
  const vendorFile = path.join(tenantDir(tenantId), '_vendors.json');
  const tmp  = vendorFile + '.tmp';
  let data;
  try { data = JSON.parse(fs.readFileSync(vendorFile, 'utf8')); } catch { data = { vendors: [] }; }

  const idx = data.vendors.findIndex(v => v.domain === vendorRecord.domain);
  if (idx >= 0) data.vendors[idx] = { ...data.vendors[idx], ...vendorRecord };
  else          data.vendors.push(vendorRecord);

  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, vendorFile);
}

module.exports = {
  persistScan,
  getBoardMetrics,
  computeQEI,
  listVendors,
  upsertVendor,
};
