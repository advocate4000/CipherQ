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
   ═══════════════════════════════════════════════════════════════════════ */

const METHOD_VERSION = 2;   /* 1 was the scanner's computeQEI, now retired */

const MAX = {
  keyEstablishment: 25,
  dataLifetime: 20,
  exposureSurface: 15,
  certificatePosture: 15,
  transportHygiene: 15,
  surfaceDiscipline: 10,
};

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
const pct = (n, d) => (d > 0 ? n / d : 0);

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

  /* ── Exposure surface (15) ────────────────────────────────────────────
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

module.exports = { computeQEI, reconcile, METHOD_VERSION, MAX };
