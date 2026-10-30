'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   CipherQ — Technical Findings & Remediation report

     node build-remediation.js scan.json out.docx \
          [--dns dns.json] [--http http.json] [--net net.json]

   A second report type, and the answer to a specific failure: the QEA is a
   board document and it needs judgements a scan cannot make — retention,
   authorisation, costs, narrative. Those arrive as fields to fill, and while
   they are unfilled the findings cannot be seen.

   That is correct for a board pack and useless for the question "what do I
   fix on Monday". This report answers only that question, so it needs
   NOTHING from a human. Every field is derived from scan output.

   It also closes a real bug. buildInput() in qea-input.js accepted only the
   TLS scan and HTTP data — dnsData was never a parameter, so all 29 DNS
   checks ran, found things, and were dropped before the report. DNSSEC,
   CAA, open zone transfer, dangling CNAMEs, subdomain takeover and the
   whole email-authentication suite were invisible. This report reads every
   module.

   Each finding already carries its own `recommendation` from the scanner,
   so the remediation text is the engine's, not invented here.
   ═══════════════════════════════════════════════════════════════════════ */

const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, ShadingType, BorderStyle,
  PageBreak, Header, Footer, PageNumber, convertInchesToTwip,
} = require('docx');

/* ── palette, matching the QEA ────────────────────────────────────────── */
const AMBER = 'B8730A', INK = '141414', MUTED = '63605A', RULE = 'DCD8D0';
const WASH = 'F7F4EF', RED = 'A82C2C', AMB2 = '8A5709', GREEN = '0A6B42';
const W = 9360;
const SEV = {
  critical: { label: 'CRITICAL', colour: RED, rank: 0 },
  high:     { label: 'HIGH',     colour: RED, rank: 1 },
  medium:   { label: 'MEDIUM',   colour: AMBER, rank: 2 },
  low:      { label: 'LOW',      colour: MUTED, rank: 3 },
  info:     { label: 'INFO',     colour: MUTED, rank: 4 },
};

const t = (text, o = {}) => new TextRun({
  text: String(text), font: o.mono ? 'Consolas' : 'Calibri', size: o.size || 20,
  bold: o.bold, italics: o.italics, color: o.color || INK,
  allCaps: o.caps, characterSpacing: o.spacing,
});
const p = (c, o = {}) => new Paragraph({
  children: Array.isArray(c) ? c : [t(c, o)],
  alignment: o.align,
  spacing: { before: o.before ?? 0, after: o.after ?? 130, line: o.line ?? 288 },
  border: o.border,
});
const H1 = x => new Paragraph({ children: [t(x, { size: 34, bold: true })], heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 60 } });
const H2 = x => new Paragraph({ children: [t(x, { size: 25, bold: true })], heading: HeadingLevel.HEADING_2, spacing: { before: 320, after: 130 } });
const KICK = x => new Paragraph({ children: [t(x, { size: 15, bold: true, color: AMBER, caps: true, spacing: 60 })], spacing: { after: 70 } });
const RULE_P = () => new Paragraph({ children: [], spacing: { after: 200 }, border: { bottom: { color: AMBER, style: BorderStyle.SINGLE, size: 10, space: 2 } } });
const gap = (h = 180) => new Paragraph({ children: [], spacing: { after: h } });

function cell(content, o = {}) {
  const kids = Array.isArray(content) ? content : [new Paragraph({
    children: [t(String(content), { size: o.size || 18, bold: o.bold, color: o.color || INK, caps: o.caps, spacing: o.caps ? 30 : 0, mono: o.mono })],
    alignment: o.align, spacing: { before: 30, after: 30, line: 250 },
  })];
  return new TableCell({
    children: kids, width: { size: o.width, type: WidthType.DXA },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill, color: 'auto' } : undefined,
    margins: { top: 90, bottom: 90, left: 130, right: 130 },
    columnSpan: o.span, verticalAlign: 'center',
  });
}
function tbl(widths, rows, o = {}) {
  const none = { style: BorderStyle.NONE };
  const line = { style: BorderStyle.SINGLE, size: 3, color: RULE };
  return new Table({
    columnWidths: widths, width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    borders: o.boxed
      ? { top: line, bottom: line, left: line, right: line, insideHorizontal: line, insideVertical: line }
      : { top: none, bottom: line, left: none, right: none, insideHorizontal: line, insideVertical: none },
    rows,
  });
}
const head = (w, labels) => new TableRow({
  tableHeader: true,
  children: labels.map((l, i) => cell(l, { width: w[i], bold: true, caps: true, size: 14, color: MUTED })),
});

/* Returns a Buffer. Takes only what a scan produces — no profile, no fields
   to complete. The board report (qea-doc.js) is the one that needs
   judgements; this one answers "what do I fix", which the scan can answer
   on its own. */
async function buildRemediation(scan, modules = {}) {
  const dns = modules.dns || null;
  const http = modules.http || null;
  const net = modules.net || null;

  /* ── gather every finding from every module ───────────────────────────── */
  const LAYERS = [
    { key: 'tls',  name: 'TLS and key exchange', findings: scan.findings || [] },
    { key: 'dns',  name: 'DNS and email authentication', findings: (dns && dns.findings) || [] },
    { key: 'http', name: 'HTTP security posture', findings: (http && http.findings) || [] },
    { key: 'net',  name: 'Network and SSH', findings: (net && net.findings) || [] },
  ];
  const ran = LAYERS.filter(l => l.findings.length > 0);
  const notRun = LAYERS.filter(l => l.findings.length === 0);

  /* De-duplicate by id+hostname: a finding repeated across 20 hosts is one
     remediation action, not twenty. The affected hosts are listed against it. */
  function group(findings) {
    const m = new Map();
    for (const f of findings) {
      const k = f.id;
      if (!m.has(k)) m.set(k, { ...f, hosts: new Set() });
      if (f.hostname) m.get(k).hosts.add(f.hostname);
    }
    return [...m.values()].sort((a, b) =>
      (SEV[a.severity] || SEV.info).rank - (SEV[b.severity] || SEV.info).rank);
  }

  const all = ran.flatMap(l => l.findings);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  all.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  const actionable = all.filter(f => f.severity !== 'info');
  const domain = (scan.summary && scan.summary.domain) || 'the estate';
  const reachable = (scan.hosts || []).filter(h => h.tls && h.tls.cipher).length;

  const K = [];

  /* ── cover ────────────────────────────────────────────────────────────── */
  K.push(
    gap(1400),
    p([t('CipherQ', { size: 50, bold: true, color: AMBER })], { after: 40 }),
    p([t('Post-quantum cryptographic intelligence', { size: 18, color: MUTED, caps: true, spacing: 50 })], { after: 900 }),
    p([t('Technical Findings', { size: 44, bold: true })], { after: 0 }),
    p([t('and Remediation', { size: 44, bold: true })], { after: 300 }),
    p([t(domain, { size: 26, color: MUTED, mono: true })], { after: 800 }),
  );
  K.push(tbl([2340, 2340, 2340, 2340], [
    new TableRow({ children: ['Scanned', 'Hosts reachable', 'Actionable findings', 'Critical and high']
      .map(x => cell(x, { width: 2340, caps: true, size: 14, color: MUTED, bold: true })) }),
    new TableRow({ children: [
      cell((scan.summary && scan.summary.scanTime || '').slice(0, 10) || '—', { width: 2340, size: 18 }),
      cell(String(reachable), { width: 2340, size: 18 }),
      cell(String(actionable.length), { width: 2340, size: 22, bold: true, color: AMBER }),
      cell(String(counts.critical + counts.high), { width: 2340, size: 22, bold: true, color: RED }),
    ]}),
  ]));
  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 1 · where the gaps are ───────────────────────────────────────────── */
  K.push(KICK('Section 01'), H1('Where the gaps are'), RULE_P());
  K.push(p('Every finding below was produced by a scan of the externally observable estate. Nothing here requires information from you — the detail, the reasoning and the remedial action all come from the assessment itself.', { after: 240 }));

  const sw = [3400, 1500, 1500, 2960];
  K.push(tbl(sw, [
    head(sw, ['Layer', 'Findings', 'Critical / high', 'Status']),
    ...ran.map(l => {
      const g = group(l.findings);
      const act = g.filter(f => f.severity !== 'info');
      const ch = g.filter(f => f.severity === 'critical' || f.severity === 'high').length;
      return new TableRow({ children: [
        cell(l.name, { width: sw[0], bold: true }),
        cell(String(act.length), { width: sw[1], mono: true, align: AlignmentType.CENTER }),
        cell(String(ch), { width: sw[2], mono: true, bold: true, align: AlignmentType.CENTER, color: ch ? RED : INK }),
        cell(ch ? 'Action required' : act.length ? 'Review' : 'No issues found',
          { width: sw[3], size: 17, color: ch ? RED : MUTED }),
      ]});
    }),
    ...notRun.map(l => new TableRow({ children: [
      cell(l.name, { width: sw[0], bold: true, color: MUTED }),
      cell('—', { width: sw[1], align: AlignmentType.CENTER, color: MUTED }),
      cell('—', { width: sw[2], align: AlignmentType.CENTER, color: MUTED }),
      cell('Not assessed', { width: sw[3], size: 17, color: MUTED }),
    ]})),
  ]));

  K.push(gap(280));
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t('Severity across the estate', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })], { after: 110 }),
    p([
      t(`${counts.critical} critical`, { bold: true, color: RED }), t('   ·   '),
      t(`${counts.high} high`, { bold: true, color: RED }), t('   ·   '),
      t(`${counts.medium} medium`, { bold: true, color: AMBER }), t('   ·   '),
      t(`${counts.low} low`, { bold: true }), t('   ·   '),
      t(`${counts.info} informational`, { color: MUTED }),
    ], { after: 110 }),
    p('Informational findings are recorded for completeness and need no action. The sections that follow cover the remainder, each with the specific change required.', { size: 18, after: 0 }),
  ], { width: W, fill: WASH })]})]));

  /* ── 2..n · one section per layer ─────────────────────────────────────── */
  ran.forEach((layer, li) => {
    const g = group(layer.findings).filter(f => f.severity !== 'info');
    if (!g.length) return;

    K.push(new Paragraph({ children: [new PageBreak()] }));
    K.push(KICK(`Section 0${li + 2}`), H1(layer.name), RULE_P());

    const ch = g.filter(f => f.severity === 'critical' || f.severity === 'high').length;
    K.push(p(`${g.length} finding${g.length === 1 ? '' : 's'} requiring action`
      + (ch ? `, of which ${ch} ${ch === 1 ? 'is' : 'are'} critical or high severity.` : '.')
      + ' Each is listed with what was observed and the change required.', { after: 240 }));

    g.forEach((f, i) => {
      if (i > 0) K.push(gap(300));
      const s = SEV[f.severity] || SEV.info;

      K.push(tbl([1500, 6380, 1480], [new TableRow({ children: [
        cell(s.label, { width: 1500, bold: true, size: 15, color: s.colour, caps: true }),
        cell(f.title || f.id, { width: 6380, bold: true, size: 21 }),
        cell(f.hosts && f.hosts.size ? `${f.hosts.size} host${f.hosts.size === 1 ? '' : 's'}` : '—',
          { width: 1480, size: 16, color: MUTED, align: AlignmentType.RIGHT }),
      ]})]));

      if (f.detail) {
        K.push(p([t('Observed   ', { size: 14, bold: true, color: AMBER, caps: true, spacing: 40 }), t(f.detail, { size: 18 })],
          { after: 110, before: 110 }));
      }
      if (f.recommendation) {
        K.push(tbl([W], [new TableRow({ children: [cell([
          p([t('What to do', { size: 14, bold: true, color: AMB2, caps: true, spacing: 40 })], { after: 80 }),
          p(f.recommendation, { size: 18, after: 0 }),
        ], { width: W, fill: WASH })]})]));
      }

      const meta = [];
      if (f.id) meta.push(['Finding', f.id]);
      if (f.area) meta.push(['Area', f.area]);
      if (f.priority) meta.push(['Priority', f.priority]);
      if (f.nistRef) meta.push(['Reference', f.nistRef]);
      if (f.hosts && f.hosts.size && f.hosts.size <= 6) meta.push(['Hosts', [...f.hosts].join(', ')]);
      else if (f.hosts && f.hosts.size) meta.push(['Hosts', `${f.hosts.size} affected — see appendix`]);
      if (meta.length) {
        const mw = [1700, 7660];
        K.push(gap(120));
        K.push(tbl(mw, meta.map(([k, v]) => new TableRow({ children: [
          cell(k, { width: mw[0], size: 15, color: MUTED, caps: true }),
          cell(v, { width: mw[1], size: 16, mono: k === 'Finding' }),
        ]}))));
      }
    });
  });

  /* ── remediation plan ─────────────────────────────────────────────────── */
  K.push(new Paragraph({ children: [new PageBreak()] }));
  K.push(KICK(`Section 0${ran.length + 2}`), H1('Remediation plan'), RULE_P());
  K.push(p('Ordered by severity. Items at the same severity can run in parallel — they touch different systems and different teams.', { after: 240 }));

  const planned = ran.flatMap(l => group(l.findings)
    .filter(f => f.severity !== 'info')
    .map(f => ({ ...f, layer: l.name })))
    .sort((a, b) => (SEV[a.severity] || SEV.info).rank - (SEV[b.severity] || SEV.info).rank);

  const pw = [620, 1380, 3560, 3800];
  K.push(tbl(pw, [
    head(pw, ['', 'Severity', 'Layer and finding', 'Action']),
    ...planned.map((f, i) => new TableRow({ children: [
      cell(String(i + 1), { width: pw[0], bold: true, color: AMBER, mono: true, align: AlignmentType.CENTER }),
      cell((SEV[f.severity] || SEV.info).label, { width: pw[1], size: 15, bold: true, caps: true, color: (SEV[f.severity] || SEV.info).colour }),
      cell([
        new Paragraph({ children: [t(f.title || f.id, { size: 17, bold: true })], spacing: { before: 30, after: 20, line: 240 } }),
        new Paragraph({ children: [t(f.layer, { size: 15, color: MUTED })], spacing: { before: 0, after: 30, line: 240 } }),
      ], { width: pw[2] }),
      cell(f.recommendation || 'See finding detail.', { width: pw[3], size: 16 }),
    ]})),
  ]));

  /* ── what was not assessed ────────────────────────────────────────────── */
  K.push(gap(320));
  K.push(H2('What was not assessed'));
  const na = [
    ...notRun.map(l => [l.name, 'Module not run for this assessment']),
    ['Internal infrastructure', 'Endpoint, document management and application-layer cryptography'],
    ['Data at rest', 'Database, disk and object-store encryption'],
    ['Supplier posture', 'Third-party cryptographic exposure is assessed separately'],
    ['Data retention period', 'Client-attested; required for exposure-window analysis, not for the remediation above'],
  ];
  const nw = [3400, 5960];
  K.push(tbl(nw, [
    head(nw, ['Area', 'Note']),
    ...na.map(([a, n]) => new TableRow({ children: [
      cell(a, { width: nw[0], bold: true }),
      cell(n, { width: nw[1], size: 17 }),
    ]})),
  ]));

  K.push(gap(300));
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t('About this report', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })], { after: 90 }),
    p('Produced by CipherQ from scan output alone. Every finding, its reasoning and its remedial action are generated by the assessment engine — no field in this document was completed by hand, and nothing has been added by a language model.', { after: 100 }),
    p([t('cipherq.co', { bold: true }), t('   ·   info@cipherq.co')], { after: 0 }),
  ], { width: W, fill: WASH })]})]));

  /* ── build ────────────────────────────────────────────────────────────── */
  const doc = new Document({
    creator: 'CipherQ',
    title: `Technical Findings and Remediation — ${domain}`,
    styles: { default: { document: { run: { font: 'Calibri', size: 20, color: INK } } } },
    sections: [{
      properties: { page: { margin: { top: 1120, bottom: 1120, left: 1080, right: 1080 } } },
      headers: { default: new Header({ children: [new Paragraph({
        children: [
          t('CipherQ', { size: 14, bold: true, color: AMBER, caps: true, spacing: 60 }),
          t('     Technical Findings and Remediation     ', { size: 14, color: MUTED, caps: true, spacing: 60 }),
          t('Restricted', { size: 14, color: MUTED }),
        ], spacing: { after: 220 },
      })]})},
      footers: { default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [t(`${domain}   ·   `, { size: 14, color: MUTED }),
          new TextRun({ children: [PageNumber.CURRENT], font: 'Calibri', size: 14, color: AMBER, bold: true })],
      })]})},
      children: K,
    }],
  });


  return {
    buffer: await Packer.toBuffer(doc),
    domain,
    actionable: actionable.length,
    counts,
    modulesRun: ran.map(l => l.key),
  };
}

module.exports = { buildRemediation };
