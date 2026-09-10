'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   Scanner output → QEA report input

   One mapping, two callers: adapt-scan.js fills the judgement fields with
   TODO markers for a consultant to complete by hand; the platform's report
   endpoint fills them from a stored client profile. They must not drift —
   this mapping has already produced four wrong numbers (KEX groups read
   from the cipher suite name, dormant records computed to zero, unreachable
   staging hosts counted as exposed environments, and an empty scan scoring
   40 out of nothing), and finding those twice in two copies is worse than
   finding them once here.
   ═══════════════════════════════════════════════════════════════════════ */

const { computeQEI } = require('./qei');
const { assessDNEL } = require('./dnel');

const TODO = s => `TODO — ${s}`;
const CRQC_YEAR = 2033;

/* Components were read positionally — components[0], [3], [4], [5]. That
   worked while the index had exactly six dimensions in a fixed order and
   broke silently the moment a seventh was inserted: an exposure would have
   printed another dimension's points as its own contribution, and nothing
   would have complained. Read by name. */
function ptsOf(scored, dimension) {
  const c = (scored.components || []).find(x => x.dimension === dimension);
  return c ? c.points : 0;
}

/* ── what the scan actually observed ──────────────────────────────────── */
function deriveFacts(scan, httpData, networkData) {
  const summary = scan.summary || {};
  const hosts = scan.hosts || [];
  const reachableHosts = hosts.filter(h => h.tls && h.tls.cipher);
  const reachable = reachableHosts.length;

  /* Confirmed only. classifyKex() returns 'classical-likely' for any TLS 1.3
     host the differential probe could not reach; treating that as
     post-quantum would be exactly the advertised-versus-negotiated confusion
     the probe exists to remove. Inconclusive counts as not confirmed. */
  const pqHosts = reachableHosts.filter(h => h.tls.kex && h.tls.kex.pqStatus === 'pq-hybrid');
  const inconclusive = reachableHosts.filter(h =>
    h.tls.kexConfirmationProbe && h.tls.kexConfirmationProbe.status === 'inconclusive');

  /* In TLS 1.3 the cipher suite name carries no key-exchange token — the
     group is negotiated separately — so TLS_AES_256_GCM_SHA384 says nothing
     about the KEX. Classification comes from the probe, not the string. */
  const groups = new Set();
  reachableHosts.forEach(h => {
    const k = h.tls.kex || {};
    if (k.pqStatus === 'pq-hybrid') { groups.add('X25519MLKEM768 (or equivalent hybrid)'); return; }
    if (k.type === 'classical-confirmed') { groups.add('Classical groups only (confirmed by differential probe)'); return; }
    if (k.type === 'ffdhe') { groups.add('FFDHE (classical)'); return; }
    if (k.type === 'rsa-kex') { groups.add('RSA key transport (classical, no forward secrecy)'); return; }
    if (k.type === 'ecdhe' || /ecdhe/i.test(h.tls.cipher || '')) { groups.add('ECDHE (classical)'); return; }
    groups.add('Not determined');
  });

  const tally = (arr, fn) => arr.reduce((m, x) => {
    const k = fn(x); if (k) m[k] = (m[k] || 0) + 1; return m;
  }, {});

  const protocols = tally(reachableHosts, h => h.tls.protocol);
  const ciphers = tally(reachableHosts, h => h.tls.cipherStandardName || h.tls.cipher);
  const issuers = tally(reachableHosts, h => h.tls.caName);
  const sigAlgs = tally(reachableHosts, h => h.tls.certSig && h.tls.certSig.name);

  const pqSigCount = reachableHosts.filter(h => h.tls.certSig && h.tls.certSig.alg === 'PQ').length;
  const expiring90 = reachableHosts.filter(h =>
    typeof h.tls.certDaysToExpiry === 'number' && h.tls.certDaysToExpiry <= 90).length;
  const mismatches = reachableHosts.filter(h => h.tls.sniMatch && h.tls.sniMatch.match === false).length;

  /* Absent an HTTP scan these are unknown, not zero. A scan that was never
     run is not a clean result. */
  const hs = httpData && httpData.summary ? httpData.summary : null;

  /* devHostsExposed is drawn from DNS naming and includes hosts that never
     answered. The report's field is dev_or_staging *reachable*, so intersect
     with the reachable set — an unreachable staging name is a
     surface-discipline problem, counted separately. */
  const reachableNames = new Set(reachableHosts.map(h => h.hostname));
  const devHosts = (summary.devHostsExposed || []).filter(n => reachableNames.has(n)).length;

  /* DNEL is assessed only where the network scan ran; dnel.js reports
     assessed:false otherwise and the index drops the dimension rather than
     scoring it zero. */
  const dnel = assessDNEL(scan, networkData);

  return {
    summary, reachableHosts, reachable,
    dnel,
    pqHosts: pqHosts.length,
    inconclusive: inconclusive.length,
    groups: [...groups],
    protocols, ciphers, issuers, sigAlgs,
    pqSigCount, expiring90, mismatches,
    hs,
    noHsts: hs ? hs.missingHSTS : null,
    noCsp: hs ? hs.missingCSP : null,
    mixed: hs ? (hs.mixedContentHosts || 0) : null,
    devHosts,
    /* Resolves in DNS, completes no handshake. NXDOMAIN names are not records. */
    dormant: summary.hostsUnreachable || 0,
    belowTls13: reachableHosts.filter(h => h.tls.protocol && h.tls.protocol !== 'TLSv1.3').length,
  };
}

function scoreFrom(f, retentionYears, assessmentYear) {
  return computeQEI({
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
    dnel: f.dnelFacts || (f.dnel && f.dnel.facts) || null,
  }, { retentionYears, assessmentYear, crqcYear: CRQC_YEAR });
}

/* Modelled index after each track, by re-running the same rules against the
   estate as it would stand. Not an estimate — the same scorer, different
   inputs. */
function project(f, retentionYears, assessmentYear) {
  const base = (f.dnel && f.dnel.facts) || null;
  /* Hybrid key establishment is one programme across TLS and SSH, so the
     key-exchange band clears the classical-auth half of the operator-access
     dimension too. It does not clear the surfaces themselves — that is the
     access band's work, and it is a firewall change rather than a crypto one. */
  const dnelAfterKex = base ? { ...base, classicalOperatorAuth: false } : null;
  /* Surfaces behind an authenticated gateway, cleartext protocols retired. */
  const dnelAfterAccess = base
    ? { ...base, classicalOperatorAuth: false, cleartextAdmin: false,
        operatorSurfaceClasses: 0, worstSurfaceWeight: 0, operatorSurfaceHosts: 0 }
    : null;

  const now = scoreFrom(f, retentionYears, assessmentYear);
  const afterKex = scoreFrom(
    { ...f, pqHosts: f.reachable, dnelFacts: dnelAfterKex }, retentionYears, assessmentYear);
  const afterAccess = scoreFrom(
    { ...f, pqHosts: f.reachable, dnelFacts: dnelAfterAccess }, retentionYears, assessmentYear);
  const afterAll = scoreFrom({
    ...f, pqHosts: f.reachable, dnelFacts: dnelAfterAccess,
    noHsts: 0, noCsp: 0, mixed: 0, devHosts: 0, dormant: 0,
  }, retentionYears, assessmentYear);
  return { now, afterKex, afterAccess, afterAll };
}

/* ── the report input ─────────────────────────────────────────────────── */
/* `profile` supplies what a scan cannot observe. Anything it does not supply
   becomes a TODO, which the generator's gate refuses to build. */
function buildInput(scan, httpData, profile = {}, networkData = null) {
  const f = deriveFacts(scan, httpData, networkData);
  if (f.reachable === 0) {
    const e = new Error('No host completed a TLS handshake in this scan; there is nothing to report on.');
    e.code = 'NOTHING_ASSESSED';
    e.detail = { probed: f.summary.hostsProbed || 0, unreachable: f.summary.hostsUnreachable || 0 };
    throw e;
  }

  const assessmentYear = profile.assessment_year || new Date().getFullYear();
  const retention = typeof profile.data_retention_years === 'number' ? profile.data_retention_years : null;

  /* Scored with a placeholder so the observable dimensions are visible in a
     draft. The gate blocks on the retention TODO regardless. */
  const p = project(f, retention === null ? 10 : retention, assessmentYear);
  const scored = p.now;
  const or = (v, todo) => (v === undefined || v === null || v === '' ? TODO(todo) : v);

  const exposures = [];
  if (f.pqHosts < f.reachable) {
    exposures.push({
      ref: 'A1', class: 'A',
      title: 'Session keys established with quantum-vulnerable cryptography',
      hosts_affected: f.reachable - f.pqHosts,
      score_contribution: ptsOf(scored, 'Key establishment'),
      observation: `${f.reachable - f.pqHosts} of ${f.reachable} reachable hosts establish session keys with `
        + `classical key exchange. `
        + (f.inconclusive ? `${f.inconclusive} host(s) returned an inconclusive probe and are counted as not confirmed. ` : '')
        + `Differential probing established negotiated capability rather than advertised preference.`,
      why_it_matters: retention === null
        ? TODO('state the retrospective consequence, referencing the client\'s retention period')
        : `Shor's algorithm recovers the private key from these constructions. Traffic recorded today can be `
          + `decrypted retrospectively once a cryptographically relevant quantum computer exists. Data retained `
          + `for ${retention} years remains confidential until ${assessmentYear + retention} — `
          + `${assessmentYear + retention - CRQC_YEAR} years beyond the ${CRQC_YEAR} estimate. The material is `
          + `already exposed; only the decryption is deferred.`,
      action: 'Enable hybrid key establishment (X25519MLKEM768) at the TLS termination point.',
      evidence: [
        { label: 'Hosts probed for key-exchange capability', value: String(f.reachable) },
        { label: 'Hosts negotiating a hybrid group', value: String(f.pqHosts) },
        { label: 'Inconclusive probes', value: String(f.inconclusive) },
        { label: 'Groups observed', value: f.groups.join(', ') || 'none recorded' },
      ],
    });
  }
  if (f.pqSigCount < f.reachable) {
    exposures.push({
      ref: 'B1', class: 'B',
      title: 'Certificate estate signed under classical PKI throughout',
      hosts_affected: f.reachable - f.pqSigCount,
      score_contribution: ptsOf(scored, 'Certificate posture'),
      observation: `${f.reachable - f.pqSigCount} of ${f.reachable} certificates use a classical signature algorithm.`,
      why_it_matters: 'Signature compromise is a forgery risk from the moment a quantum computer exists, not a '
        + 'retrospective one — it does not expose historic sessions. Recorded so the distinction from Class A is explicit.',
      action: 'No immediate action. Include post-quantum signature support in certificate authority selection criteria at next renewal.',
      evidence: [
        { label: 'Certificates examined', value: String(f.reachable) },
        { label: 'Post-quantum signatures', value: String(f.pqSigCount) },
        { label: 'Signature algorithms', value: Object.keys(f.sigAlgs).join(', ') || 'not determined' },
        { label: 'Retrospective exposure', value: 'None' },
      ],
    });
  }
  if (f.noHsts) {
    exposures.push({
      ref: 'C1', class: 'C',
      title: `${f.noHsts} hosts serve no HTTP Strict Transport Security header`,
      hosts_affected: f.noHsts,
      score_contribution: ptsOf(scored, 'Transport hygiene'),
      observation: `${f.noHsts} of ${f.reachable} reachable hosts return no HSTS header; ${f.noCsp} serve no Content-Security-Policy.`,
      why_it_matters: 'A present-day risk, unrelated to quantum computing. Included because a post-quantum programme '
        + 'cannot credibly be built on an estate with unresolved transport hygiene. These run alongside the '
        + 'key-establishment work, not ahead of it — nothing here reduces retrospective exposure.',
      action: 'Set HSTS with a max-age of at least one year on all public hosts and submit the apex for preloading.',
      evidence: [
        { label: 'Hosts without HSTS', value: `${f.noHsts} of ${f.reachable}` },
        { label: 'Hosts without CSP', value: `${f.noCsp} of ${f.reachable}` },
      ],
    });
  }
  if (f.devHosts > 0) {
    exposures.push({
      ref: 'C2', class: 'C',
      title: 'Development or staging infrastructure externally reachable',
      hosts_affected: f.devHosts,
      score_contribution: ptsOf(scored, 'Surface discipline'),
      observation: `Discovery surfaced ${f.summary.hostsProbed || 0} host names, of which ${f.reachable} are reachable. `
        + `${f.devHosts} match development or staging naming conventions. A further ${f.dormant} resolve in DNS but complete no handshake.`,
      why_it_matters: 'Non-production infrastructure is routinely configured to weaker standards than production and '
        + 'is a recognised initial-access route.',
      action: 'Restrict non-production hosts to known source addresses or an authenticated gateway. Audit the dormant records.',
      evidence: [
        { label: 'Host names discovered', value: String(f.summary.hostsProbed || 0) },
        { label: 'Reachable', value: String(f.reachable) },
        { label: 'Non-production reachable', value: String(f.devHosts) },
        { label: 'Dormant DNS records', value: String(f.dormant) },
      ],
    });
  }

  /* ── Class D — operational ────────────────────────────────────────────
     Deploy Now, Exploit Later. Distinct from Class A and Class B in what the
     adversary does, not merely in what it costs: they neither decrypt nor
     forge. They present authentication material that is genuinely valid
     because the client issued it, and log on. Only raised where the network
     scan actually ran — the surfaces are discovered from open ports, and an
     unrun scan is not a clean estate. */
  const D = f.dnel;
  if (D.assessed && D.facts.operatorSurfaceClasses > 0) {
    /* Labels as written — lower-casing turned 'OT / ICS control' into
       'ot / ics control' in the report body. */
    const classList = D.surfaces.map(x => x.label).join(', ');
    exposures.push({
      ref: 'D1', class: 'D',
      title: 'Operator authentication reachable under recoverable cryptography',
      hosts_affected: D.applicableHosts,
      score_contribution: ptsOf(scored, 'Operational access'),
      observation: `${D.applicableHosts} of ${D.totalHosts} hosts expose an operator-authentication `
        + `surface (${classList}). `
        + (D.ssh.scanned
            ? `${D.ssh.classical} of ${D.ssh.scanned} SSH hosts negotiate classical key exchange only. `
            : '')
        + (D.facts.cleartextAdmin
            ? 'A cleartext administration protocol is reachable, so the credential is recoverable '
              + 'today with no quantum step required. '
            : '')
        + (D.facts.credentialsOutlivingHorizon
            ? `${D.facts.credentialsOutlivingHorizon} operator-facing credential(s) remain valid `
              + `beyond the ${CRQC_YEAR} estimate.`
            : ''),
      why_it_matters: 'At Q-Day an adversary holding recovered authentication material does not need '
        + 'to decrypt anything or forge anything. They authenticate. The session is well-formed, the '
        + 'credential is one you issued and still trust, and there is no anomaly for a monitoring '
        + 'control to catch — which is the practical difference from Class B, where a forged artifact '
        + 'at least exists to be examined. Non-repudiation fails in the same moment: the audit trail '
        + 'faithfully records an authorised operator performing authorised actions.'
        + (D.surfaces.some(x => x.key === 'ot-ics')
            ? ' Process-control equipment carries this furthest. A 10–30 year replacement cycle means '
              + 'what is deployed now is what is still running at Q-Day, and equipment that is '
              + 'certification- or hardware-locked cannot be re-keyed at any price.'
            : ''),
      action: 'Place operator surfaces behind an authenticated, PQ-capable gateway; enable hybrid key '
        + 'establishment on the management plane as well as on TLS; cap operator credential lifetimes '
        + 'so harvested material expires inside the migration window; and record the crypto-agility '
        + 'constraint for equipment that cannot be re-keyed.',
      evidence: [
        { label: 'Hosts exposing an operator surface', value: `${D.applicableHosts} of ${D.totalHosts}` },
        { label: 'Surface classes reachable', value: classList },
        { label: 'SSH hosts without hybrid key exchange',
          value: D.ssh.scanned ? `${D.ssh.classical} of ${D.ssh.scanned}` : 'not probed' },
        { label: 'Cleartext administration reachable', value: D.facts.cleartextAdmin ? 'Yes' : 'No' },
        { label: 'Credentials valid beyond the CRQC estimate',
          value: String(D.facts.credentialsOutlivingHorizon) },
      ],
    });
  }

  const rate = profile.rate_card || {};
  const owners = profile.owners || {};
  const board = profile.board || {};

  return {
    _generated: {
      by: 'qea-input.js',
      at: new Date().toISOString(),
      scan_time: f.summary.scanTime || null,
      qei_method_version: scored.method_version,
    },
    client: {
      name: or(profile.name, 'client legal entity name'),
      sector: or(profile.sector, 'sector, e.g. Legal & Professional Services'),
      domain: f.summary.domain || or(null, 'primary domain'),
      date_issued: profile.date_issued || new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }),
      classification: profile.classification || 'Restricted — Client Confidential',
      prepared_by: 'CipherQ',
      data_retention_years: retention === null
        ? TODO('years the client must keep this data confidential — drives the entire exposure window, worth 20 index points; get this in writing')
        : retention,
      retention_basis: or(profile.retention_basis, 'the actual obligation, e.g. "Client matter files retained 15 years under SRA requirements"'),
      regulations: (profile.regulations && profile.regulations.length)
        ? profile.regulations : [TODO('applicable regimes, e.g. FCA, GDPR, SOC 2')],
    },
    assessment: {
      qei: scored.qei,
      /* The denominator is not always 100: qei.js drops unassessed dimensions
         from it rather than scoring them zero, so an estate with no network
         scan is scored out of 85. Carrying it through is what stops the report
         understating an estate it only partly measured. */
      qei_max: scored.qeiMax,
      complete: scored.complete,
      band: scored.band,
      crqc_estimate: CRQC_YEAR,
      assessment_year: assessmentYear,
      scan_window: f.summary.scanTime ? f.summary.scanTime.slice(0, 10) : or(null, 'scan window'),
      authorisation: or(profile.authorisation, 'written authorisation reference — required before any active probing'),
      components: scored.components,
    },
    board: {
      position_good: or(board.position_good, 'what is competent about this estate — say it plainly, it buys credibility for the rest'),
      position_bad: or(board.position_bad, 'the gap, framed against their own obligation rather than against peers'),
      exposure_statement: or(board.exposure_statement, 'the retrospective consequence in the client\'s own terms'),
      ask_headline: or(board.ask_headline, 'the figure and the timeframe — must match the investment table total'),
      ask_detail: or(board.ask_detail, 'the two tracks and who owns each'),
      outcome: or(board.outcome, 'modelled index after the work'),
      if_deferred: or(board.if_deferred, 'what a month of delay costs'),
      decision: or(board.decision, 'the decision being put to the board'),
      decision_owner: or(board.decision_owner, 'recommended accountable owner'),
    },
    assurance: [
      { area: 'Key-exchange groups', method: 'Active — differential probing', status: 'Verified', confidence: 'High' },
      { area: 'Protocol and cipher', method: 'Active — TLS handshake', status: 'Verified', confidence: 'High' },
      { area: 'Certificate chain', method: 'Active — chain retrieval', status: 'Verified', confidence: 'High' },
      { area: 'HTTP security headers',
        method: f.hs ? 'Active — response inspection' : 'Not assessed',
        status: f.hs ? 'Verified' : 'Out of scope',
        confidence: f.hs ? 'High' : '—' },
      { area: 'Host surface', method: 'Passive — Certificate Transparency, DNS', status: 'Verified', confidence: 'High' },
      { area: 'Operator access surface',
        method: f.dnel.assessed ? 'Active — port and service probing' : 'Not assessed',
        status: f.dnel.assessed ? 'Verified' : 'Out of scope',
        confidence: f.dnel.assessed ? 'High' : '—' },
      { area: 'Crypto-agility constraint per asset', method: 'Not assessed — requires attested import',
        status: 'Out of scope', confidence: '—' },
      { area: 'Data retention period', method: 'Client-declared', status: 'Inferred', confidence: 'Client attestation' },
      { area: 'Internal cryptography', method: 'Not assessed', status: 'Out of scope', confidence: '—' },
      { area: 'Supplier posture', method: 'Not assessed', status: 'Out of scope', confidence: '—' },
    ],
    scope: {
      hosts_discovered: f.summary.hostsProbed || 0,
      hosts_probed: f.summary.hostsProbed || 0,
      hosts_reachable: f.reachable,
      discovery_method: f.summary.ctLog && f.summary.ctLog.enabled
        ? 'Certificate Transparency logs and public DNS' : 'Public DNS',
      handshakes_performed: typeof f.summary.handshakesPerformed === 'number'
        ? f.summary.handshakesPerformed
        : or(profile.handshakes_performed, 'total handshakes — the scanner does not yet count these; add a counter or state the probe multiplier'),
    },
    kex: {
      hosts_with_pq_kex: f.pqHosts,
      groups_observed: f.groups,
      pq_groups_offered: f.pqHosts ? ['X25519MLKEM768 (or equivalent hybrid)'] : [],
      downgrade_findings: `All ${f.reachable} reachable hosts completed a handshake. `
        + `${f.pqHosts} negotiated a hybrid post-quantum group. `
        + (f.inconclusive ? `${f.inconclusive} probe(s) were inconclusive and are counted as classical. ` : '')
        + `Each TLS 1.3 host was offered a handshake restricted to hybrid groups to establish actual capability `
        + `rather than advertised preference.`,
    },
    tls: { protocols: f.protocols, ciphers: f.ciphers },
    certificates: {
      total: f.reachable,
      issuers: f.issuers,
      signature_algorithms: f.sigAlgs,
      pq_signature_count: f.pqSigCount,
      expiring_90d: f.expiring90,
      sni_mismatches: f.mismatches,
    },
    http: f.hs ? {
      hsts_present: f.reachable - f.noHsts,
      hsts_absent: f.noHsts,
      csp_present: f.reachable - f.noCsp,
      csp_absent: f.noCsp,
      mixed_content_hosts: f.mixed,
    } : null,
    surface: {
      dormant_dns_records: f.dormant,
      dev_or_staging_reachable: f.devHosts,
    },
    dnel: f.dnel.assessed ? {
      index: f.dnel.index,
      band: f.dnel.band.label,
      operator_surface_hosts: f.dnel.applicableHosts,
      hosts_considered: f.dnel.totalHosts,
      classes: f.dnel.surfaces.map(x => ({ label: x.label, hosts: x.hosts })),
      ssh_scanned: f.dnel.ssh.scanned,
      ssh_classical_kex: f.dnel.ssh.classical,
      cleartext_admin: f.dnel.facts.cleartextAdmin,
      credentials_outliving_horizon: f.dnel.facts.credentialsOutlivingHorizon,
      not_yet_observable: f.dnel.gaps.map(g => g.label),
    } : null,
    exposures,
    sequence: [
      { step: 1, track: 'Class A — key establishment', action: 'Confirm CDN or load balancer supports hybrid key exchange', depends_on: '—', effort: 'Days', owner: or(owners.security, 'owning team for key establishment') },
      { step: 2, track: 'Class A — key establishment', action: 'Enable X25519MLKEM768 on the highest-value host, canary first', depends_on: 'Step 1', effort: 'Weeks', owner: or(owners.security, 'owning team for key establishment') },
      { step: 3, track: 'Class A — key establishment', action: 'Extend hybrid key exchange to mail and remaining hosts', depends_on: 'Step 2', effort: 'Weeks', owner: or(owners.security, 'owning team for key establishment') },
      ...(f.dnel.assessed && f.dnel.facts.operatorSurfaceClasses > 0 ? [
        { step: 4, track: 'Class D — operator access', action: 'Enable hybrid key exchange on the SSH management plane (OpenSSH 9.0+) and rotate host keys', depends_on: '—', effort: 'Weeks', owner: or(owners.security, 'owning team for key establishment') },
        { step: 5, track: 'Class D — operator access', action: 'Place reachable operator surfaces behind an authenticated gateway; retire any cleartext administration protocol', depends_on: '—', effort: 'Weeks', owner: or(owners.operations, 'owning team for hygiene') },
        { step: 6, track: 'Class D — operator access', action: 'Cap operator credential lifetimes so no classically-signed credential outlives the migration window', depends_on: 'Step 5', effort: 'Days', owner: or(owners.security, 'owning team for key establishment') },
      ] : []),
      { step: 7, track: 'Class C — present-day hygiene', action: 'Set HSTS across all public hosts', depends_on: '—', effort: 'Days', owner: or(owners.operations, 'owning team for hygiene') },
      { step: 8, track: 'Class C — present-day hygiene', action: 'Restrict non-production hosts to known sources', depends_on: '—', effort: 'Days', owner: or(owners.operations, 'owning team for hygiene') },
      { step: 9, track: 'Class C — present-day hygiene', action: 'Audit and remove dormant DNS records', depends_on: '—', effort: 'Weeks', owner: or(owners.operations, 'owning team for hygiene') },
    ],
    projection: {
      qei_now: p.now.qei,
      qei_after_kex: p.afterKex.qei,
      qei_after_access: p.afterAccess.qei,
      qei_after_all: p.afterAll.qei,
      residual_explanation: or(profile.residual_explanation,
        'why the index does not reach zero for this client'),
      investment: [
        { band: 'Enable hybrid key establishment', window: '0–6 months',
          low: or(rate.kex_low, 'your rate card'), high: or(rate.kex_high, 'your rate card'),
          qei_delta: p.now.qei - p.afterKex.qei },
        ...(f.dnel.assessed && f.dnel.facts.operatorSurfaceClasses > 0 ? [
          { band: 'Close operator-access exposures', window: '0–3 months',
            low: or(rate.access_low, 'your rate card'), high: or(rate.access_high, 'your rate card'),
            qei_delta: p.afterKex.qei - p.afterAccess.qei },
        ] : []),
        { band: 'Close Class C exposures', window: '0–2 months',
          low: or(rate.hygiene_low, 'your rate card'), high: or(rate.hygiene_high, 'your rate card'),
          qei_delta: p.afterAccess.qei - p.afterAll.qei },
      ],
    },
    verification: [
      { measure: 'Hosts negotiating hybrid key exchange', today: `${f.pqHosts} of ${f.reachable}`,
        target: `${f.reachable} of ${f.reachable}`, verified_by: 'Re-scan, differential probe' },
      { measure: 'Externally reachable non-production hosts', today: String(f.devHosts),
        target: '0', verified_by: 'Re-scan, CT discovery' },
      ...(f.dnel.assessed ? [
        { measure: 'SSH hosts negotiating hybrid key exchange',
          today: f.dnel.ssh.scanned ? `${f.dnel.ssh.pqReady} of ${f.dnel.ssh.scanned}` : 'not probed',
          target: f.dnel.ssh.scanned ? `${f.dnel.ssh.scanned} of ${f.dnel.ssh.scanned}` : '—',
          verified_by: 'Re-scan, SSH KEXINIT probe' },
        { measure: 'Hosts exposing an operator-authentication surface',
          today: String(f.dnel.applicableHosts), target: '0',
          verified_by: 'Re-scan, port and service probe' },
      ] : []),
      { measure: 'Quantum Exposure Index', today: String(p.now.qei),
        target: `Under ${p.afterAll.qei + 4}`, verified_by: 'Full re-assessment' },
    ],
  };
}

module.exports = { deriveFacts, scoreFrom, project, buildInput, TODO, CRQC_YEAR };
