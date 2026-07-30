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
const QEI_METHOD_VERSION = 1;

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
// 0 = perfect PQ posture; 100 = maximum exposure
// Driven by: PQ readiness of reachable hosts, KEX status, cert posture, HNDL risk

// Fallback only: approximates a QEI for scan records persisted before the
// qei-consolidation fix (F16), which only have the lightweight stored
// summary fields (not the full scanResult), so it can't use the same
// computation as computeQEI(). Every scan persisted after this fix stores
// its QEI directly via computeQEI() at persist time — this function should
// only ever run against historical data.
function estimateLegacyQEI(scanRecord) {
  const pb = scanRecord.pqReadinessBreakdown || {};
  const total = scanRecord.hostsReachable || 1;
  let qei = 0;
  qei += Math.round((pb.none    || 0) / total * 50);
  qei += Math.round((pb.unknown || 0) / total * 30);
  qei -= Math.round((pb.ready   || 0) / total * 30);
  if (scanRecord.overallHndlRisk === 'high') qei += 20;
  else if (scanRecord.overallHndlRisk === 'high-likely') qei += 15;
  qei += Math.min(15, (scanRecord.findingsBySeverity?.critical || 0) * 3);
  return Math.max(0, Math.min(100, qei));
}

function computeQEI(scanResult, dnsData, httpData, networkData) {
  const { summary, hosts } = scanResult;
  const reachable = hosts.filter(h => h.tls?.cipher);

  let score = 0;

  // — KEX posture (0-50 pts) ———————————————————————————————
  if (reachable.length > 0) {
    const pqNone    = reachable.filter(h => h.pqReadiness === 'none').length;
    const pqUnknown = reachable.filter(h => h.pqReadiness === 'unknown').length;
    const pqReady   = reachable.filter(h => h.pqReadiness === 'ready').length;

    const pqNonePct    = pqNone    / reachable.length;
    const pqUnknownPct = pqUnknown / reachable.length;
    const pqReadyPct   = pqReady   / reachable.length;

    score += Math.round(pqNonePct    * 50);
    score += Math.round(pqUnknownPct * 30);
    score -= Math.round(pqReadyPct   * 30);
  } else {
    score += 20; // no reachable hosts = cannot assess
  }

  // — HNDL risk label (0-20 pts) ———————————————————————————
  if (summary.overallHndlRisk === 'high')         score += 20;
  else if (summary.overallHndlRisk === 'high-likely') score += 15;
  else if (summary.overallHndlRisk === 'partial') score += 8;

  // — Critical TLS findings (0-15 pts) ————————————————————
  const criticalTLS = (scanResult.findings || []).filter(
    f => f.severity === 'critical' && f.area?.startsWith('tls')
  ).length;
  score += Math.min(15, criticalTLS * 5);

  // — Dev hosts / SNI mismatches (0-10 pts) ———————————————
  score += Math.min(10, (summary.devHostsExposed?.length || 0) * 3 +
                        (summary.sniMismatches?.length   || 0) * 2);

  // — DNS security deductions (-5 pts for good posture) ————
  const ds = dnsData?.report?.summary || {};
  if (ds.dnssecDeployed) score -= 5;
  if (ds.dmarcPolicy === 'reject') score -= 3;
  if (!ds.axfrVulnerable && dnsData) score -= 2;

  // — SSH (0-5 pts) ————————————————————————————————————————
  const ns = networkData?.summary || {};
  if (ns.sshHostsScanned > 0 && ns.sshPQReady < ns.sshHostsScanned) {
    score += Math.min(5, (ns.sshHostsScanned - ns.sshPQReady) * 2);
  }

  return Math.max(0, Math.min(100, score));
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
  const qei = computeQEI(scanResult, dnsData, httpData, networkData);

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
      quantumExposureTrend: null,
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
  const qeiMethodVersion = hasStoredQEI ? latestScan.qeiMethodVersion : 0;

  let qeiTrend = null;
  if (prevScan) {
    const prevHasStored = typeof prevScan.qei === 'number';
    const qeiPrev = prevHasStored ? prevScan.qei : estimateLegacyQEI(prevScan);
    qeiTrend = qei - qeiPrev;
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
    quantumExposureTrend: qeiTrend,
    qeiMethodVersion, // 0 = legacy pre-consolidation estimate; see computeQEI/estimateLegacyQEI
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
