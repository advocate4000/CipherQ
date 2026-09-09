'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   Quantum Exposure Index — the six-dimension methodology

   This is the score the report defends in front of a client, and it is now
   the only one. The scanner's older computeQEI() weighted KEX 0-50, an HNDL
   label 0-20, critical TLS findings 0-15, dev hosts 0-10, DNS -10 and SSH
   0-5. Both produced a 0-100 number and both were called a QEI, which meant
   a scan reading 61 and a report reading 74 could describe the same estate.

   Two differences mattered enough to settle it this way:

     - This methodology has a data-lifetime dimension. Retention against the
       CRQC estimate is the report's central argument, and a score that
       ignores it cannot express why a 15-year firm is in more trouble than
       a 2-year one with identical infrastructure.
     - Every dimension here decomposes into points, a maximum, and the
       observation that produced them. "Critical TLS findings x 5" does not
       survive a client asking where the number came from.

   Bump METHOD_VERSION whenever a weight or an input changes, so an index of
   74 computed today and one computed next year cannot be silently compared.

   ── v3: operational access (DNEL) ─────────────────────────────────────
   Version 3 adds a seventh dimension for Deploy Now, Exploit Later — the
   exposure created when an adversary presents genuine authentication
   material rather than decrypting traffic (HNDL) or forging an artifact
   (TNFL). See dnel.js for the threat model and the port classification.

   The 15 points it carries were taken from dimensions that either overlap
   with it or are explicitly not quantum exposures, leaving the two that
   carry the report's central argument untouched:

     exposure surface    15 → 10   a raw reachable-host count; operational
                                   access now measures what KIND of surface,
                                   which is the more informative half
     transport hygiene   15 → 11   present-day risk, scored for programme
                                   credibility rather than quantum exposure
     certificate posture 15 → 12   forward-only, already deliberately below
                                   key establishment
     surface discipline  10 →  7   overlaps directly — a reachable dev host
                                   and a reachable operator surface are
                                   adjacent observations
     key establishment   25 → 25   untouched: the retrospective argument
     data lifetime       20 → 20   untouched: the report's central argument

   Every existing score moves as a result. That is the point of the version
   stamp: getBoardMetrics suppresses the trend across the boundary rather
   than presenting the shift as progress.

   Operational access is unassessed when the network scan has not run, and
   drops from the denominator exactly as data lifetime does. An estate that
   was never port-scanned is not an estate with no exposed operator surface.
   ═══════════════════════════════════════════════════════════════════════ */

const METHOD_VERSION = 3;   /* 1 = retired scanner scorer · 2 = pre-DNEL six-dimension */

const MAX = {
  keyEstablishment: 25,
  dataLifetime: 20,
  operationalAccess: 15,
  exposureSurface: 10,
  certificatePosture: 12,
  transportHygiene: 11,
  surfaceDiscipline: 7,
};

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
const pct = (n, d) => (d > 0 ? n / d : 0);

/* Operational access, 0–15. Lives here rather than in dnel.js so the number
   exists once: dnel.js classifies ports and raises findings, this computes
   the index contribution, and the projection in qea-input.js can re-run it
   against a modelled estate by mutating the same facts.

   Scored as the worst operator surface class present, plus a little for
   breadth, plus the state of the cryptography authenticating to it. A
   surface that is PQ-ready still scores, because the surface exists; it
   simply scores far less than one whose key exchange is recoverable. */
function operationalAccessPoints(d) {
  if (!d || !d.operatorSurfaceClasses) return 0;
  const surfacePts = clamp(
    (d.worstSurfaceWeight || 0) + Math.min(3, Math.max(0, d.operatorSurfaceClasses - 1)), 0, 10);
  const cryptoPts = d.classicalOperatorAuth ? 3 : 0;
  const cleartextPts = d.cleartextAdmin ? 2 : 0;
  return clamp(surfacePts + cryptoPts + cleartextPts, 0, MAX.operationalAccess);
}

/**
 * facts — everything observable from a scan:
 *   reachable, hostsWithPqKex, hostsTls13,
 *   certsExpiring90d, sniMismatches, allCertsPq,
 *   hostsNoHsts, hostsNoCsp, mixedContentHosts, hostsBelowTls13,
 *   devOrStagingReachable, dormantDnsRecords
 * client — the part a scan cannot see:
 *   retentionYears, assessmentYear, crqcYear
 */
function computeQEI(facts, client) {
  const f = facts, c = client;
  const comp = [];

  /* ── Key establishment (25) ───────────────────────────────────────────
     Driven by what hosts will actually negotiate. An estate already on
     TLS 1.3 is a configuration change away from hybrid key exchange; one
     still on 1.2 needs a stack upgrade first. That difference is worth up
     to 3 points, because it changes the cost of the remedy, not the fact
     of the exposure. */
  const pqShare = pct(f.hostsWithPqKex, f.reachable);
  let keyPts = MAX.keyEstablishment * (1 - pqShare);
  const tls13Share = pct(f.hostsTls13, f.reachable);
  keyPts -= 3 * tls13Share * (1 - pqShare);
  keyPts = f.reachable === 0 ? MAX.keyEstablishment : Math.round(keyPts);
  comp.push({
    dimension: 'Key establishment',
    points: clamp(keyPts, 0, MAX.keyEstablishment),
    max: MAX.keyEstablishment,
    note: f.hostsWithPqKex === 0
      ? `No post-quantum key exchange on any reachable host`
      : `${f.hostsWithPqKex} of ${f.reachable} hosts negotiate a hybrid group`,
  });

  /* ── Data lifetime (20) ───────────────────────────────────────────────
     The only dimension a scan cannot supply. Overrun is the number of years
     data must stay confidential beyond the point the cryptography protecting
     it is expected to fail. Zero or negative overrun scores zero: a firm
     that discards data before the CRQC estimate has no retrospective
     exposure, and the report should say so rather than manufacture urgency.

     Retention may be unknown — the platform scores every scanned domain, and
     the figure is client-attested. Unknown is not zero. The dimension is
     marked unassessed and dropped from the denominator, so the dashboard
     shows 54 of 80 rather than passing 54 off as a score out of 100. */
  const known = typeof c.retentionYears === 'number' && isFinite(c.retentionYears);
  const horizon = known ? c.assessmentYear + c.retentionYears : null;
  const overrun = known ? horizon - c.crqcYear : null;
  comp.push(known ? {
    dimension: 'Data lifetime',
    points: overrun <= 0 ? 0 : clamp(Math.round(4 + overrun * 1.5), 0, MAX.dataLifetime),
    max: MAX.dataLifetime,
    note: overrun <= 0
      ? `${c.retentionYears}-year retention places horizon at ${horizon}, inside the CRQC estimate`
      : `${c.retentionYears}-year retention places horizon at ${horizon}, ${overrun} years past the CRQC estimate`,
  } : {
    dimension: 'Data lifetime',
    points: 0,
    max: MAX.dataLifetime,
    unassessed: true,
    note: 'Retention period not supplied — client-attested, cannot be observed',
  });

  /* ── Operational access (15) — DNEL ───────────────────────────────────
     Deploy Now, Exploit Later. Not what an adversary can read or forge, but
     what they can log in to using material that is genuinely theirs to
     present because you issued it. Unassessed without a network scan: the
     surfaces are discovered from open ports, and an unrun scan is not a
     clean result. */
  const dn = f.dnel || null;
  comp.push(dn && dn.networkScanRan ? {
    dimension: 'Operational access',
    points: operationalAccessPoints(dn),
    max: MAX.operationalAccess,
    note: dn.operatorSurfaceClasses
      ? `${dn.operatorSurfaceHosts} host(s) expose an operator-authentication surface across `
        + `${dn.operatorSurfaceClasses} class(es)`
        + (dn.classicalOperatorAuth ? ', authenticated under classical key establishment' : '')
        + (dn.cleartextAdmin ? '; cleartext administration protocol reachable' : '')
      : 'No operator-authentication surface reachable',
  } : {
    dimension: 'Operational access',
    points: 0,
    max: MAX.operationalAccess,
    unassessed: true,
    note: 'Network scan not run — operator surfaces are discovered from open ports',
  });

  /* ── Exposure surface (10) ────────────────────────────────────────────
     Reachable hosts, not discovered hosts. A dormant DNS record is a
     surface-discipline problem, not an exposure. */
  comp.push({
    dimension: 'Exposure surface',
    points: clamp(Math.round(f.reachable / 2), 0, MAX.exposureSurface),
    max: MAX.exposureSurface,
    note: `${f.reachable} internet-facing hosts completing a TLS handshake`,
  });

  /* ── Certificate posture (15) ─────────────────────────────────────────
     Signature compromise is forward-only, so this is deliberately weighted
     below key establishment despite covering the same hosts. */
  let certPts = 0;
  const certNotes = [];
  /* No reachable hosts means no certificates were retrieved. Scoring "classical
     PKI throughout" against an estate we never saw would be inventing a
     finding. */
  if (f.reachable === 0) certNotes.push('no certificates observed');
  else if (!f.allCertsPq) { certPts += 6; certNotes.push('classical PKI throughout'); }
  if (f.certsExpiring90d > 0) { certPts += 1; certNotes.push(`${f.certsExpiring90d} expiring within 90 days`); }
  if (f.sniMismatches > 0) { certPts += 1; certNotes.push(`${f.sniMismatches} subject mismatch`); }
  comp.push({
    dimension: 'Certificate posture',
    points: clamp(certPts, 0, MAX.certificatePosture),
    max: MAX.certificatePosture,
    note: certNotes.length ? certNotes.join('; ') : 'Post-quantum signatures in use; no immediate weakness',
    _unassessed: f.reachable === 0,
  });

  /* ── Transport hygiene (15) ───────────────────────────────────────────
     Present-day risk, unrelated to quantum. Scored because a post-quantum
     programme is not credible on an estate with unresolved basics. */
  const hstsPts = Math.round(8 * pct(f.hostsNoHsts, f.reachable));
  const cspPts = Math.round(5 * pct(f.hostsNoCsp, f.reachable));
  const mixedPts = clamp(f.mixedContentHosts, 0, 1);
  const legacyPts = clamp(Math.round(f.hostsBelowTls13 / 2), 0, 2);
  comp.push({
    dimension: 'Transport hygiene',
    points: clamp(hstsPts + cspPts + mixedPts + legacyPts, 0, MAX.transportHygiene),
    max: MAX.transportHygiene,
    note: `${f.hostsNoHsts} without HSTS, ${f.hostsNoCsp} without CSP`
      + (f.hostsBelowTls13 ? `, ${f.hostsBelowTls13} below TLS 1.3` : ''),
  });

  /* ── Surface discipline (10) ──────────────────────────────────────────
     What the estate advertises that it need not. */
  const devPts = clamp(f.devOrStagingReachable * 2, 0, 6);
  const dnsPts = clamp(Math.floor(f.dormantDnsRecords / 12), 0, 4);
  comp.push({
    dimension: 'Surface discipline',
    points: clamp(devPts + dnsPts, 0, MAX.surfaceDiscipline),
    max: MAX.surfaceDiscipline,
    note: `${f.devOrStagingReachable} reachable non-production hosts, ${f.dormantDnsRecords} dormant DNS records`,
  });

  const scored = comp.filter(x => !x.unassessed);
  const qei = scored.reduce((s, x) => s + x.points, 0);
  const qeiMax = scored.reduce((s, x) => s + x.max, 0);

  /* Bands are proportional, so a partial index is banded against what was
     actually assessed rather than against 100. */
  const share = qeiMax > 0 ? qei / qeiMax : 0;
  return {
    qei,
    qeiMax,
    complete: qeiMax === 100,
    band: share >= 0.7 ? 'HIGH' : share >= 0.4 ? 'MEDIUM' : 'LOW',
    components: comp,
    method_version: METHOD_VERSION,
    horizon,
    overrun,
  };
}

/* Guards a hand-edited scan file: the report prints the components as a table
   with the index as its total row, so they have to add up. */
function reconcile(assessment) {
  const sum = (assessment.components || []).filter(x => !x.unassessed)
    .reduce((s, x) => s + x.points, 0);
  return sum === assessment.qei
    ? { ok: true }
    : { ok: false, sum, stated: assessment.qei };
}

module.exports = { computeQEI, reconcile, operationalAccessPoints, METHOD_VERSION, MAX };
