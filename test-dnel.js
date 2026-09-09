'use strict';
/* End-to-end check: mock estate → qea-input → qei → qea-doc → .docx
   Run: node test-dnel.js */

const { buildInput, deriveFacts, project } = require('./qea-input');
const { computeQEI, MAX, METHOD_VERSION } = require('./qei');
const { assessDNEL } = require('./dnel');

const DAY = 86400000;
const dTo = y => Math.round((new Date(y, 5, 1) - new Date()) / DAY);

const mkHost = (hostname, o = {}) => Object.assign({
  hostname,
  dns: { resolves: true, aRecords: ['203.0.113.10'] },
  findings: [],
  pqReadiness: 'none', hndlRisk: 'high-likely', tnflRisk: 'high', riskScore: 55,
}, o);

const tls = (o = {}) => Object.assign({
  protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', cipherStandardName: 'TLS_AES_256_GCM_SHA384',
  certDaysToExpiry: 70, caName: "Let's Encrypt", caClassical: true,
  sniMatch: { match: true, detail: '' },
  kex: { pqStatus: 'classical-likely', type: 'ecdhe', label: 'X25519' },
  certSig: { name: 'ECDSA-SHA256', alg: 'classical', pqStatus: 'quantum-vulnerable' },
}, o);

/* A critical-infrastructure estate: OT protocols, a directory, a bastion,
   a VPN concentrator, a legacy RTU on telnet, and one ordinary web host. */
const scan = {
  summary: {
    domain: 'example-utility.com', scanTime: new Date().toISOString(),
    hostsProbed: 12, hostsReachable: 5, hostsUnreachable: 7, hostsNxdomain: 0,
    findingsTotal: 3,
    findingsBySeverity: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
    pqReadinessBreakdown: { none: 5, unknown: 0, partial: 0, ready: 0 },
    protocolsObserved: ['TLSv1.3', 'TLSv1.2'], ciphersObserved: ['TLS_AES_256_GCM_SHA384'],
    casObserved: ["Let's Encrypt", 'Internal Utility CA'],
    sniMismatches: [], devHostsExposed: [], overallHndlRisk: 'high-likely',
    ctLog: { enabled: true, hostsDiscovered: 12, totalCerts: 21, error: null },
    handshakesPerformed: 34,
  },
  hosts: [
    mkHost('scada-gw.example-utility.com', { tls: tls({ protocol: 'TLSv1.2', certDaysToExpiry: dTo(2034), caName: 'Internal Utility CA', kex: { pqStatus: 'classical', type: 'ecdhe' } }) }),
    mkHost('bastion.example-utility.com',  { tls: tls() }),
    mkHost('ad.example-utility.com',       { tls: tls({ protocol: 'TLSv1.2', certDaysToExpiry: dTo(2031), caName: 'Internal Utility CA', kex: { pqStatus: 'classical', type: 'ecdhe' } }) }),
    mkHost('vpn.example-utility.com',      { tls: tls({ caName: 'DigiCert' }) }),
    mkHost('www.example-utility.com',      { tls: tls() }),
    mkHost('legacy-rtu.example-utility.com', { tls: null, hndlRisk: 'unknown', tnflRisk: 'unknown' }),
  ],
  findings: [
    { id: 'KEX-PQ-STATUS-UNKNOWN', hostname: 'www.example-utility.com', severity: 'high', area: 'tls', title: 'No hybrid PQ key exchange', detail: 'x', recommendation: 'y', priority: 'P1', nistRef: 'FIPS 203' },
  ],
};

const networkData = {
  summary: { ipsScanned: 6, openPortsTotal: 14, criticalPorts: 5, sshHostsScanned: 3, sshPQReady: 0, smtpHostsScanned: 0, smtpStartTLS: 0 },
  report: { portScans: [
    { hostname: 'scada-gw.example-utility.com',   openPorts: [{ port: 502, proto: 'tcp', banner: 'Modbus' }, { port: 20000, proto: 'tcp', banner: 'DNP3' }, { port: 22, proto: 'tcp', banner: 'OpenSSH_8.2' }] },
    { hostname: 'bastion.example-utility.com',    openPorts: [{ port: 22, proto: 'tcp', banner: 'OpenSSH_9.6' }, { port: 3389, proto: 'tcp', banner: 'RDP' }] },
    { hostname: 'ad.example-utility.com',         openPorts: [{ port: 88, proto: 'tcp' }, { port: 389, proto: 'tcp' }, { port: 636, proto: 'tcp' }] },
    { hostname: 'vpn.example-utility.com',        openPorts: [{ port: 500, proto: 'udp' }, { port: 4500, proto: 'udp' }] },
    { hostname: 'legacy-rtu.example-utility.com', openPorts: [{ port: 23, proto: 'tcp', banner: 'Telnet' }, { port: 102, proto: 'tcp', banner: 'S7' }] },
    { hostname: 'www.example-utility.com',        openPorts: [{ port: 443, proto: 'tcp', banner: 'nginx' }] },
  ]},
  findings: [],
};

const httpData = { summary: { missingHSTS: 3, missingCSP: 4, mixedContentHosts: 0 }, findings: [] };

const profile = {
  name: 'Example Utility plc', sector: 'Energy & Utilities',
  data_retention_years: 12,
  retention_basis: 'Operational records retained 12 years under licence conditions',
  regulations: ['NIS2', 'GDPR'],
  authorisation: 'ENG-2026-0114',
  residual_explanation: 'Residual index reflects reachable-host count, which the programme does not reduce.',
  owners: { security: 'Security Engineering', operations: 'Platform Operations' },
  rate_card: { kex_low: 40000, kex_high: 65000, hygiene_low: 8000, hygiene_high: 14000, access_low: 25000, access_high: 45000 },
  board: {
    position_good: 'TLS 1.3 across most of the estate and a short certificate lifecycle.',
    position_bad: 'No hybrid key establishment anywhere, and process control reachable from the internet.',
    exposure_statement: 'Operational records must stay confidential to 2038, five years past the estimate.',
    ask_headline: '£73,000 – £124,000 over six months',
    ask_detail: 'Three tracks: key establishment, operator access, and transport hygiene.',
    outcome: 'Modelled index falls to the low twenties.',
    if_deferred: 'Each month adds a month of recorded traffic and harvested credentials.',
    decision: 'Approve the six-month programme and name an accountable owner.',
    decision_owner: 'Chief Information Security Officer',
  },
};

console.log('── qei.js ──');
console.log('METHOD_VERSION', METHOD_VERSION, '· maxima total', Object.values(MAX).reduce((a, b) => a + b, 0));

console.log('\n── DNEL, standalone ──');
const d = assessDNEL(scan, networkData);
console.log('assessed', d.assessed, '· index', d.index, d.band.label, '· dimension points', d.points, '/', d.max);
d.hosts.forEach(h => console.log('   ', h.hostname.padEnd(34), String(h.score).padStart(4), h.band.label, h.applicable ? '' : '(no operator surface)'));
console.log('   findings:', d.findings.map(f => `[${f.severity}] ${f.title}`).join('\n              '));

console.log('\n── DNEL unassessed (no network scan) ──');
const d0 = assessDNEL(scan, null);
console.log('assessed', d0.assessed, '· points', d0.points, '· gaps', d0.gaps.length);

console.log('\n── index, with and without the network scan ──');
const fWith = deriveFacts(scan, httpData, networkData);
const fWithout = deriveFacts(scan, httpData, null);
for (const [label, f] of [['with network scan', fWith], ['without', fWithout]]) {
  const q = computeQEI({
    reachable: f.reachable, hostsWithPqKex: f.pqHosts,
    hostsTls13: f.reachableHosts.filter(h => h.tls.protocol === 'TLSv1.3').length,
    certsExpiring90d: f.expiring90, sniMismatches: f.mismatches,
    allCertsPq: false, hostsNoHsts: f.noHsts, hostsNoCsp: f.noCsp, mixedContentHosts: f.mixed,
    hostsBelowTls13: f.belowTls13, devOrStagingReachable: f.devHosts, dormantDnsRecords: f.dormant,
    dnel: f.dnel.facts,
  }, { retentionYears: 12, assessmentYear: 2026, crqcYear: 2033 });
  console.log(`${label.padEnd(20)} ${q.qei} / ${q.qeiMax}  ${q.band}  complete=${q.complete}`);
  q.components.forEach(c => console.log(`     ${c.dimension.padEnd(22)} ${String(c.points).padStart(3)} / ${String(c.max).padStart(3)}${c.unassessed ? '   UNASSESSED' : ''}`));
}

console.log('\n── projection ──');
const pr = project(fWith, 12, 2026);
console.log('now', pr.now.qei, '→ afterKex', pr.afterKex.qei, '→ afterAccess', pr.afterAccess.qei, '→ afterAll', pr.afterAll.qei);

console.log('\n── report input ──');
const input = buildInput(scan, httpData, profile, networkData);
console.log('exposures:', input.exposures.map(e => `${e.ref} (Class ${e.class}, +${e.score_contribution})`).join(', '));
console.log('investment bands:', input.projection.investment.map(x => `${x.band} −${x.qei_delta}`).join(' | '));
console.log('sequence tracks:', [...new Set(input.sequence.map(x => x.track))].join(' | '));
console.log('dnel block present:', !!input.dnel);

module.exports = { scan, networkData, httpData, profile, input };
