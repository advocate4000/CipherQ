'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   DNEL — Deploy Now, Exploit Later

   The third quantum risk axis, alongside the hndlRisk and tnflRisk already
   carried on every host record.

     HNDL  Confidentiality.  Traffic recorded today is read once a CRQC
                             exists. Retrospective.
     TNFL  Authenticity.     A recovered signing key MINTS NEW trusted
                             artifacts — forged certificates, forged
                             updates. Forward.
     DNEL  Access.           The adversary presents GENUINE authentication
                             material that is legitimately in the trust
                             store. Nothing is forged. There is no anomaly
                             to detect, because the credential is real and
                             the session is well-formed. Non-repudiation
                             fails with it: the audit trail faithfully
                             records an authorised operator.

   The boundary against TNFL is the whole point and it is a detection
   difference, not a rhetorical one. Forgery leaves an artifact that can be
   examined — a chain to pin, a provenance to check. DNEL leaves nothing:
   the credential was issued by you and is still valid.

   ── WHAT IS SCORED ────────────────────────────────────────────────────
   Two conditions must hold together:

     1. an operator-authentication surface is reachable, and
     2. the material authenticating to it is quantum-vulnerable, recoverable
        today, or outlives the CRQC estimate.

   Neither alone is DNEL. An exposed static web host is not a DNEL asset —
   it scores not-applicable, not a reassuring zero. Reporting "low risk" for
   an asset that was never in scope for this axis is how an index loses its
   credibility, so the distinction is kept explicit.

   ── EVIDENCE ──────────────────────────────────────────────────────────
   Operator surfaces are discovered from open ports, so this module is only
   assessed when the network scan has run. Without it the dimension reports
   assessed:false and qei.js drops it from the denominator — exactly as it
   handles an unsupplied retention period. An unrun scan is not a clean
   estate.

   This module is the single source of truth for DNEL. The UI reads the
   `dnel` block off the network scan response rather than recomputing it;
   cbom.js and qea-input.js read the same block. The platform has already
   been bitten once by two independent scorers for one concept (see the
   note at the top of qei.js) and this axis does not repeat it.
   ═══════════════════════════════════════════════════════════════════════ */

/* The index contribution is computed by qei.js, not here. This module owns
   the port classification, the per-host detail and the findings; qei.js owns
   the arithmetic that turns those facts into index points, so the number
   exists in one place and the projection in qea-input.js can re-run it
   against a modelled estate. */
const { operationalAccessPoints, MAX } = require('./qei');

const CRQC_YEAR = 2033;
const DEPRECATION_YEAR = 2030;   /* NIST IR 8547 — RSA-2048 and ECC P-256 */

const MAX_POINTS = MAX.operationalAccess;   /* the operational-access dimension of the QEI */

/* ── Operator-authentication surfaces ──────────────────────────────────
   Two scales, named apart because they answer different questions and
   conflating them let the server and the UI fallback disagree by a point:

     weight      0–10, feeds the operational-access dimension of the QEI
     hostWeight  0–46, feeds the per-host estate score shown in the UI

   Both reflect how directly the port fronts an operator login AND how
   hard the asset behind it is to re-key. OT scores highest: a 10–30 year
   replacement cycle means what is deployed now is what is still running at
   Q-Day, and much of it cannot accept new cryptography at any price. That
   is the "deploy now" half of the name, and it is the half neither
   harvest-based threat model covers. */
const SURFACES = [
  {
    key: 'ot-ics', hostWeight: 46, label: 'OT / ICS control', weight: 8,
    ports: [102, 502, 789, 1911, 2404, 4911, 9600, 20000, 44818, 47808],
    note: 'Process control reachable from outside. Replacement cycles of 10–30 years make this the '
        + 'asset class least able to be re-keyed before a CRQC exists.',
  },
  {
    key: 'directory-auth', hostWeight: 42, label: 'Directory & authentication', weight: 7,
    ports: [88, 389, 636, 1812, 1813, 3268, 3269],
    note: 'The credential issuer itself. Compromise here is estate-wide rather than host-local.',
  },
  {
    key: 'orchestration', hostWeight: 36, label: 'Orchestration & cluster APIs', weight: 6,
    ports: [2375, 2376, 2379, 2380, 6443, 10250],
    note: 'Control-plane credentials, typically long-lived and rarely rotated.',
  },
  {
    key: 'vpn-tunnel', hostWeight: 34, label: 'VPN & tunnel concentrators', weight: 5,
    ports: [500, 1194, 4500, 51820],
    note: 'Grants network position rather than host access alone. Handshakes recorded today yield '
        + 'the session keys later.',
  },
  {
    key: 'remote-admin', hostWeight: 34, label: 'Remote administration', weight: 4,
    ports: [22, 23, 3389, 5900, 5901, 5985, 5986],
    note: 'Direct interactive operator access. The canonical DNEL entry point.',
  },
];

/* Credential recoverable today, with no quantum step required at all. */
const CLEARTEXT_PORTS = [23, 2375];
/* Credential-bearing services with no guaranteed outer TLS layer. */
const WEAK_AUTH_PORTS = [389, 1812, 1813];

const BANDS = [
  { min: 70, key: 'critical', label: 'CRITICAL' },
  { min: 50, key: 'high',     label: 'HIGH' },
  { min: 28, key: 'elevated', label: 'ELEVATED' },
  { min: 1,  key: 'low',      label: 'LOW' },
  { min: 0,  key: 'not-applicable', label: 'N/A' },
];

const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
const band = score => BANDS.find(b => score >= b.min) || BANDS[BANDS.length - 1];
const surfaceForPort = port => SURFACES.find(s => s.ports.includes(parseInt(port, 10))) || null;

/**
 * @param {object} scanResult  result of scanDomain()
 * @param {object} [networkData]  result of scanNetworkSecurity() — { report, summary }
 * @returns {object} the DNEL assessment
 */
function assessDNEL(scanResult, networkData) {
  const hosts = (scanResult && scanResult.hosts) || [];
  const portScans = networkData && networkData.report && networkData.report.portScans;
  const assessed = Array.isArray(portScans);

  const portsByHost = {};
  if (assessed) {
    for (const ps of portScans) {
      portsByHost[ps.hostname] = (ps.openPorts || []).map(p => ({
        port: parseInt(p.port, 10), proto: p.proto, banner: p.banner || '',
      }));
    }
  }

  /* The network scan reports SSH posture as estate counts rather than per
     host, so a shortfall is attributed to the estate and said plainly,
     not guessed onto a hostname. */
  const nsum = (networkData && networkData.summary) || {};
  const sshScanned = nsum.sshHostsScanned || 0;
  const sshPQReady = nsum.sshPQReady || 0;
  const sshClassical = Math.max(0, sshScanned - sshPQReady);

  const now = new Date();
  const crqcDays = Math.max(0, (new Date(CRQC_YEAR, 0, 1) - now) / 86400000);
  const deprDays = Math.max(0, (new Date(DEPRECATION_YEAR, 0, 1) - now) / 86400000);

  const results = [];
  const tally = {};
  SURFACES.forEach(s => { tally[s.key] = { hosts: 0, ports: 0, def: s }; });

  for (const h of hosts) {
    const open = portsByHost[h.hostname] || [];
    const matched = [];
    const seen = {};
    const reasons = [];
    let baseWeight = 0;
    let extraClasses = 0;

    for (const p of open) {
      const s = surfaceForPort(p.port);
      if (!s) continue;
      matched.push({ port: p.port, surface: s.key, label: s.label, banner: p.banner });
      tally[s.key].ports++;
      if (!seen[s.key]) {
        seen[s.key] = true;
        tally[s.key].hosts++;
        if (s.hostWeight > baseWeight) baseWeight = s.hostWeight;
        else extraClasses++;
        reasons.push({ kind: 'surface', evidence: 'observed',
          text: `${s.label} reachable (port ${p.port})` });
      }
    }

    if (!matched.length) {
      results.push({
        hostname: h.hostname, score: 0, band: band(0), surfaces: [], reasons: [],
        applicable: false, evidence: assessed ? 'observed' : 'not-collected',
      });
      continue;
    }

    /* Scored as the WORST surface present plus a small increment per
       additional class — two doors are worse than one, not twice as bad.
       An earlier additive form rated every host with an SSH port as
       critical, which makes the metric useless. */
    const base = baseWeight + Math.min(18, extraClasses * 6);

    /* How vulnerable is the authentication to that surface? A multiplier,
       not an addend. A PQ-ready surface still carries some exposure because
       the surface exists at all — but not the same exposure as one whose
       key exchange is recoverable. */
    let factor = 0.45;
    let flat = 0;

    const cleartext = matched.filter(m => CLEARTEXT_PORTS.includes(m.port));
    if (cleartext.length) {
      factor = 1.0; flat += 25;
      reasons.push({ kind: 'crypto', evidence: 'observed',
        text: `Cleartext administration protocol on port ${cleartext[0].port} — the credential is `
            + `recoverable today, with no quantum step required` });
    }

    const weakAuth = matched.filter(m => WEAK_AUTH_PORTS.includes(m.port));
    if (weakAuth.length) {
      flat += 10;
      reasons.push({ kind: 'crypto', evidence: 'observed',
        text: `Credential-bearing service on port ${weakAuth[0].port} exposed without a guaranteed `
            + `outer TLS layer` });
    }

    const kex = h.tls && h.tls.kex && h.tls.kex.pqStatus;
    if (kex && kex !== 'pq-hybrid') {
      factor += 0.25;
      reasons.push({ kind: 'crypto', evidence: 'observed',
        text: `Key exchange is ${kex} — session material recorded now yields the authentication `
            + `exchange later` });
    }

    const hasSSH = matched.some(m => m.port === 22);
    if (hasSSH && sshClassical > 0) {
      factor += 0.20;
      reasons.push({ kind: 'crypto', evidence: 'observed-estate',
        text: `SSH management plane: ${sshClassical} of ${sshScanned} probed hosts negotiate `
            + `classical key exchange only` });
    }

    const sig = h.tls && h.tls.certSig && h.tls.certSig.pqStatus;
    if (sig === 'quantum-vulnerable') {
      factor += 0.10;
      reasons.push({ kind: 'crypto', evidence: 'observed',
        text: 'Host identity asserted by a quantum-vulnerable certificate signature' });
    }
    factor = Math.min(1.0, factor);

    /* The "deploy now" half: material issued today under classical
       algorithms that is still trusted when it can no longer be trusted. */
    const days = h.tls && h.tls.certDaysToExpiry;
    if (typeof days === 'number' && days > 0) {
      if (days > crqcDays) {
        flat += 12;
        reasons.push({ kind: 'lifetime', evidence: 'observed',
          text: `Certificate remains valid past the ${CRQC_YEAR} CRQC estimate — a credential `
              + `deployed now that is still trusted then` });
      } else if (days > deprDays) {
        flat += 6;
        reasons.push({ kind: 'lifetime', evidence: 'observed',
          text: `Certificate remains valid past the ${DEPRECATION_YEAR} NIST IR 8547 deprecation `
              + `of RSA-2048 and ECC P-256` });
      }
    }

    const score = clamp(Math.round(base * factor + flat), 0, 100);
    results.push({
      hostname: h.hostname, score, band: band(score), surfaces: matched, reasons,
      applicable: true, evidence: 'observed',
    });
  }

  const applicable = results.filter(r => r.applicable);
  const surfaces = SURFACES
    .map(s => ({ key: s.key, label: s.label, note: s.note, weight: s.weight,
                 hosts: tally[s.key].hosts, ports: tally[s.key].ports }))
    .filter(s => s.hosts > 0);

  /* ── The QEI dimension ───────────────────────────────────────────────
     Facts here, arithmetic in qei.js. */
  const worstWeight = surfaces.reduce((m, s) => Math.max(m, s.weight), 0);   /* QEI scale */
  const anyCleartext = applicable.some(r => r.reasons.some(x => /Cleartext/.test(x.text)));
  const anyClassicalAuth = sshClassical > 0
    || applicable.some(r => r.reasons.some(x => x.kind === 'crypto' && /Key exchange is/.test(x.text)));

  const noteParts = [];
  if (!surfaces.length) noteParts.push('No operator-authentication surface reachable');
  else {
    noteParts.push(`${applicable.length} of ${results.length} hosts expose an operator surface `
      + `(${surfaces.map(s => s.label).join(', ')})`);
    if (anyClassicalAuth) noteParts.push('authenticated under classical key establishment');
    if (anyCleartext) noteParts.push('cleartext administration protocol reachable');
  }

  /* ── Findings, in the shape every other scanner module emits ───────── */
  const findings = [];
  for (const s of surfaces) {
    const withIt = applicable.filter(r => r.surfaces.some(m => m.surface === s.key));
    findings.push({
      id: `DNEL-${s.key.toUpperCase()}-EXPOSED`,
      severity: (s.key === 'ot-ics' || s.key === 'directory-auth') ? 'critical' : 'high',
      area: 'dnel-operator-access',
      hostname: withIt.slice(0, 4).map(r => r.hostname).join(', ')
        + (withIt.length > 4 ? ` +${withIt.length - 4} more` : ''),
      title: `${s.label} reachable on ${s.hosts} host${s.hosts === 1 ? '' : 's'}`,
      detail: `${s.note} An adversary holding recovered authentication material for this surface `
            + `does not breach anything — they authenticate. The session is well-formed, the `
            + `credential is genuine, and the audit trail records an authorised operator.`,
      recommendation: s.key === 'ot-ics'
        ? 'Remove direct internet reachability and place behind an authenticated, PQ-capable gateway. '
          + 'Record the crypto-agility constraint per device: equipment that is certification- or '
          + 'hardware-locked cannot be remediated by patching and must be scheduled as replacement.'
        : 'Enable hybrid post-quantum key establishment on this surface, shorten credential lifetimes '
          + 'so harvested material expires inside the migration window, and require re-issue rather '
          + 'than renewal at the next rotation.',
      nistRef: 'SC-8 · SC-12 · AC-3 | NIST FIPS 203 | CNSA 2.0',
      priority: s.key === 'ot-ics' ? 'P1' : 'P2',
    });
  }

  const cleartextHosts = applicable.filter(r => r.reasons.some(x => /Cleartext/.test(x.text)));
  if (cleartextHosts.length) {
    findings.push({
      id: 'DNEL-CLEARTEXT-ADMIN', severity: 'critical', area: 'dnel-operator-access',
      hostname: cleartextHosts.map(r => r.hostname).join(', '),
      title: 'Cleartext administration protocol exposed',
      detail: 'Operator credentials traverse this service unencrypted. This is a DNEL exposure that '
            + 'needs no quantum computer at all — the credential is harvestable today and will still '
            + 'authenticate whenever it is used.',
      recommendation: 'Disable the service and rotate every credential that has traversed it.',
      nistRef: 'SC-8 · IA-5 | CNSA 2.0', priority: 'P1',
    });
  }

  if (sshClassical > 0) {
    findings.push({
      id: 'DNEL-SSH-CLASSICAL-KEX', severity: 'high', area: 'dnel-operator-access', hostname: '',
      title: `${sshClassical} of ${sshScanned} SSH hosts negotiate classical key exchange`,
      detail: 'SSH is the operator plane. A recorded classical handshake yields the session keys once '
            + 'a CRQC exists, and with them the authentication exchange inside that session. Host keys '
            + 'and authorised user keys are long-lived by convention, so the exposure persists across '
            + 'the whole harvest window rather than expiring with the session.',
      recommendation: 'Enable mlkem768x25519-sha256 hybrid key exchange (OpenSSH 9.0+), then rotate '
            + 'host keys and re-issue user keys so pre-migration material stops being accepted.',
      nistRef: 'SC-8 · SC-12 | NIST FIPS 203 | NIST IR 8547', priority: 'P1',
    });
  }

  const longLived = applicable.filter(r => r.reasons.some(x => x.kind === 'lifetime'));
  if (longLived.length) {
    findings.push({
      id: 'DNEL-CREDENTIAL-LIFETIME', severity: 'medium', area: 'dnel-operator-access',
      hostname: longLived.slice(0, 4).map(r => r.hostname).join(', '),
      title: `${longLived.length} operator-facing credential${longLived.length === 1 ? '' : 's'} `
           + `outlive the migration window`,
      detail: 'These credentials are valid beyond the point at which the algorithms underwriting them '
            + 'are deprecated or breakable. This is the "deploy now" half of DNEL: material issued '
            + 'today, under classical cryptography, still being trusted when it can no longer be.',
      recommendation: 'Cap credential lifetime for operator-facing services so no certificate issued '
            + 'under classical algorithms remains valid past the deprecation date.',
      nistRef: 'SC-12 · SC-17 | NIST IR 8547', priority: 'P2',
    });
  }

  /* Estate figure for the UI. Weighted toward the worst asset: an estate is
     as exposed as its most reachable operator surface, not as its average
     host. Distinct from `points`, which is the QEI contribution. */
  let index = 0;
  if (applicable.length) {
    const sorted = applicable.slice().sort((a, b) => b.score - a.score);
    const worst = sorted[0].score;
    const mean = sorted.reduce((s, r) => s + r.score, 0) / sorted.length;
    index = Math.round(worst * 0.6 + mean * 0.4);
  }

  const facts = {
    networkScanRan: assessed,
    operatorSurfaceHosts: applicable.length,
    operatorSurfaceClasses: surfaces.length,
    worstSurfaceWeight: worstWeight,
    cleartextAdmin: anyCleartext,
    classicalOperatorAuth: anyClassicalAuth,
    sshClassicalKex: sshClassical,
    credentialsOutlivingHorizon: longLived.length,
  };

  return {
    assessed,
    index, band: band(index),
    points: operationalAccessPoints(facts), max: MAX_POINTS,
    note: noteParts.join('; '),
    hosts: results,
    applicableHosts: applicable.length,
    totalHosts: results.length,
    surfaces,
    findings,
    ssh: { scanned: sshScanned, pqReady: sshPQReady, classical: sshClassical },
    crqcYear: CRQC_YEAR,
    gaps: evidenceGaps(assessed),
    /* What qei.js consumes. Flat and named, so the dimension can be
       re-scored against a modelled estate without this module rerunning. */
    facts,
  };
}

/* Signals that bear on DNEL and are not yet collected. Naming them keeps the
   score honest: a low figure with three of these open is a low figure about
   the part that was visible. */
function evidenceGaps(assessed) {
  const gaps = [];
  if (!assessed) {
    gaps.push({ key: 'network-scan', label: 'Network & port scan not run',
      detail: 'Operator surfaces are discovered from open ports. Without the network scan this axis '
            + 'is unassessed and drops out of the index denominator rather than scoring zero.' });
  }
  gaps.push({ key: 'agility', label: 'Crypto-agility constraint per asset',
    detail: 'Whether a device can accept new cryptography at all — field-upgradable, firmware-locked, '
          + 'certification-locked or hardware-locked. Not observable over the wire; needs attested '
          + 'import. The single largest determinant of real DNEL exposure, and the largest gap.' });
  gaps.push({ key: 'idp', label: 'Identity provider signing posture',
    detail: 'OIDC discovery and JWKS publish id_token signing algorithms and key types directly, and '
          + 'parse like a certificate. This is the operator authentication layer and is fetchable '
          + 'without credentials — already scoped as Phase 1 in the endpoint coverage matrix.' });
  gaps.push({ key: 'mtls', label: 'Client certificate / mTLS requirement',
    detail: 'Whether a surface authenticates its clients cryptographically, and under which '
          + 'algorithms. Detectable by probing for a CertificateRequest in the handshake.' });
  return gaps;
}

module.exports = { assessDNEL, SURFACES, MAX_POINTS, CRQC_YEAR, BANDS };
