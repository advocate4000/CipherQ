'use strict';
/* QEA report route — a drop-in handler for POST /api/report.
 *
 * This exists so wiring the QEA report into server.js is two lines rather than
 * a hand-edit of a request handler I cannot see:
 *
 *     const qeaRoute = require('./qea-route');
 *     app.post('/api/report', qeaRoute.handler({ reportProfile }));
 *
 * It owns the whole contract the frontend already expects — the 409 profile
 * gate, the Content-Disposition filename, the error shapes — so there is
 * nothing left to get subtly wrong at the call site.
 *
 * `report.js` (generateReport) is deliberately not referenced here. The two
 * generators produce different documents from different inputs, and having one
 * route able to emit either is how an estate ends up with two reports that
 * disagree. Pick one at the route.
 */

const { buildInput } = require('./qea-input');
const { build, validate } = require('./qea-doc');

/** Domain from the request body, however the caller spelled it. */
function domainOf(body) {
  return (
    body.domain ||
    (body.scanResult && body.scanResult.summary && body.scanResult.summary.domain) ||
    'unknown'
  );
}

function safeFilenameSegment(s) {
  return String(s).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 100) || 'unknown';
}

/**
 * Build the Express handler.
 *
 * @param {object} deps
 * @param {object} deps.reportProfile  the ./report-profile module
 * @param {function} [deps.loadProfile] (domain, req) => profile | Promise<profile>.
 *        Defaults to reportProfile.read(domain). Override if your profiles are
 *        tenant-scoped — the signature gives you the request to key off.
 * @param {function} [deps.log]        (level, msg, meta) => void
 */
function handler(deps = {}) {
  const reportProfile = deps.reportProfile || require('./report-profile');
  const log = deps.log || (() => {});
  const loadProfile =
    deps.loadProfile || ((domain) => reportProfile.read(domain));

  return async function qeaReportHandler(req, res) {
    const body = req.body || {};
    const domain = domainOf(body);

    try {
      const scanResult = body.scanResult;
      if (!scanResult || !scanResult.summary || !Array.isArray(scanResult.hosts)) {
        return res.status(400).json({
          error: 'scanResult is required, with summary and hosts.',
        });
      }

      const profile = (await loadProfile(domain, req)) || {};

      /* The fourth argument is the whole point. Without it assessDNEL reports
         assessed:false, the operational-access dimension leaves the
         denominator, and the document silently loses Class D and its section
         while still validating. */
      const input = buildInput(
        scanResult,
        body.httpData || null,
        profile,
        body.networkData || null
      );

      /* Context-aware gate: the two operator-access rates are only required
         where the scan actually found a reachable operator surface, so an
         estate with none is not blocked on a rate for work it does not need. */
      const accessTrack = !!(
        input.dnel && input.dnel.operator_surface_hosts > 0
      );
      const missing = reportProfile.missing(profile, { accessTrack });
      if (missing.length) {
        log('info', 'report profile incomplete', { domain, missing: missing.length });
        return res.status(409).json({
          error: 'Report profile incomplete.',
          domain,
          missing,
        });
      }

      /* Never ship a document that failed its own checks. A report with an
         outstanding TODO or an index that does not reconcile against its own
         components is worse than no report — it is a document a client may act
         on. */
      const v = validate(input);
      if (!v.ok) {
        log('error', 'report failed validation', {
          domain,
          todos: v.todos.length,
          reconciles: v.reconciles,
        });
        return res.status(500).json({
          error: 'Report did not validate and was not produced.',
          reconciles: v.reconciles,
          reconcile: v.reconcile,
          todos: v.todos,
        });
      }

      const { buffer, sections } = await build(input);

      const filename =
        'CipherQ_QEA_' +
        safeFilenameSegment(domain) +
        '_' +
        new Date().toISOString().slice(0, 10) +
        '.docx';

      log('info', 'report built', {
        domain,
        bytes: buffer.length,
        sections: sections.length,
        dnel: accessTrack,
        qei: input.assessment.qei,
        qei_max: input.assessment.qei_max,
      });

      res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      );
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', buffer.length);
      /* The figure and the method version travel with the file, so a report
         found on disk months later can still be traced to how it was scored. */
      res.setHeader('X-CipherQ-QEI', String(input.assessment.qei));
      res.setHeader('X-CipherQ-QEI-Max', String(input.assessment.qei_max));
      res.setHeader('X-CipherQ-Sections', String(sections.length));
      return res.send(buffer);
    } catch (err) {
      log('error', 'report generation failed', { domain, message: err.message });
      return res.status(500).json({
        error: 'Report generation failed.',
        message: err.message,
      });
    }
  };
}

/**
 * Attach DNEL to a network scan result, in place, and fold its findings into
 * the summary counts. Call at the end of POST /api/network-scan, before
 * responding.
 *
 * The report does NOT need this — buildInput computes DNEL from the raw
 * networkData itself. This is so the UI and the CBOM read the server's figure
 * rather than the client's fallback, which keeps one scorer behind one concept.
 *
 * @param {object} result     the network scan result you are about to return
 * @param {Array}  tlsHosts   req.body.hosts — carries the TLS blocks DNEL needs
 */
function attachDNEL(result, tlsHosts) {
  const { assessDNEL } = require('./dnel');
  result.dnel = assessDNEL({ hosts: tlsHosts || [] }, result);
  result.findings = (result.findings || []).concat(result.dnel.findings || []);
  result.summary = result.summary || {};
  result.summary.bySeverity = ['critical', 'high', 'medium', 'low', 'info'].reduce(
    (m, s) => ((m[s] = result.findings.filter((f) => f.severity === s).length), m),
    {}
  );
  result.summary.totalFindings = result.findings.length;
  return result;
}

module.exports = { handler, attachDNEL };
