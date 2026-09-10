'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   CipherQ — Quantum Exposure Assessment generator

     node build-qta.js scan-example.json "Client QEA.docx"

   Architecture is evidence-led rather than narrative-led. Exposures are
   classified by threat model (retrospective / forward / present-day), every
   score decomposes into attributable components, and an assurance register
   states what was verified against what was inferred.
   ═══════════════════════════════════════════════════════════════════════ */

const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, ShadingType, BorderStyle,
  PageBreak, Header, Footer, PageNumber, LevelFormat, convertInchesToTwip,
} = require('docx');

const { reconcile } = require('./qei');

/* ── Palette ───────────────────────────────────────────────────────── */
const AMBER = 'B8730A';
const INK   = '141414';
const MUTED = '63605A';
const RULE  = 'DCD8D0';
const WASH  = 'F7F4EF';
const RED   = 'A82C2C';
const GREEN = '0A6B42';
const BRONZE= '7A4A08';   /* Class D — in the amber family, distinct from AMBER */
const W     = 9360;

const money = n => '£' + n.toLocaleString('en-GB');
const CLASS_NAME = {
  A: 'Class A — Retrospective',
  B: 'Class B — Forward',
  C: 'Class C — Present-day',
  D: 'Class D — Operational',
};
const CLASS_TONE = { A: RED, B: AMBER, C: MUTED, D: BRONZE };
const CLASS_LABEL = {
  A: 'Retrospective exposures',
  B: 'Forward exposures',
  C: 'Present-day exposures',
  D: 'Operational exposures',
};
/* Order matters: the classes are emitted, tabulated and sequenced in this
   order everywhere, so it is stated once. */
const CLASSES = ['A', 'B', 'C', 'D'];

/* ── Primitives ────────────────────────────────────────────────────── */
const t = (text, o = {}) => new TextRun({
  text, font: o.mono ? 'Consolas' : 'Calibri', size: o.size || 20,
  bold: o.bold, italics: o.italics, color: o.color || INK,
  allCaps: o.caps, characterSpacing: o.spacing,
});

const p = (content, o = {}) => new Paragraph({
  children: Array.isArray(content) ? content : [t(content, o)],
  alignment: o.align,
  spacing: { before: o.before ?? 0, after: o.after ?? 130, line: o.line ?? 288 },
  border: o.border,
});

const H1 = text => new Paragraph({
  children: [t(text, { size: 34, bold: true })],
  heading: HeadingLevel.HEADING_1,
  spacing: { before: 360, after: 60 },
});

const H2 = text => new Paragraph({
  children: [t(text, { size: 25, bold: true })],
  heading: HeadingLevel.HEADING_2,
  spacing: { before: 320, after: 130 },
});

const KICKER = text => new Paragraph({
  children: [t(text, { size: 15, bold: true, color: AMBER, caps: true, spacing: 60 })],
  spacing: { before: 0, after: 70 },
});

const RULE_P = () => new Paragraph({
  children: [], spacing: { after: 200 },
  border: { bottom: { color: AMBER, style: BorderStyle.SINGLE, size: 10, space: 2 } },
});

const gap = (h = 180) => new Paragraph({ children: [], spacing: { after: h } });

function cell(content, o = {}) {
  const kids = Array.isArray(content) ? content : [new Paragraph({
    children: [t(String(content), {
      size: o.size || 18, bold: o.bold, color: o.color || INK,
      caps: o.caps, spacing: o.caps ? 30 : 0, mono: o.mono,
    })],
    alignment: o.align,
    spacing: { before: 30, after: 30, line: 250 },
  })];
  return new TableCell({
    children: kids,
    width: { size: o.width, type: WidthType.DXA },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill, color: 'auto' } : undefined,
    margins: { top: 100, bottom: 100, left: 140, right: 140 },
    columnSpan: o.span,
    verticalAlign: 'center',
  });
}

function lines(list, o = {}) {
  const arr = list.length ? list : ['—'];
  return cell(arr.map(l => new Paragraph({
    children: [t(String(l), { size: o.size || 17, bold: o.bold, color: o.color || INK, mono: o.mono })],
    spacing: { before: 25, after: 25, line: 240 },
  })), o);
}

/* Rules used sparingly — horizontal separators only, no boxed grid */
function tbl(widths, rows, o = {}) {
  const none = { style: BorderStyle.NONE };
  const line = { style: BorderStyle.SINGLE, size: 3, color: RULE };
  return new Table({
    columnWidths: widths,
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    borders: o.boxed
      ? { top: line, bottom: line, left: line, right: line, insideHorizontal: line, insideVertical: line }
      : { top: none, bottom: line, left: none, right: none, insideHorizontal: line, insideVertical: none },
    rows,
  });
}

const head = (widths, labels) => new TableRow({
  tableHeader: true,
  children: labels.map((l, i) => cell(l, {
    width: widths[i], bold: true, caps: true, size: 14, color: MUTED,
  })),
});

const bullets = items => items.map(x => new Paragraph({
  children: [t(x)],
  numbering: { reference: 'cq', level: 0 },
  spacing: { before: 40, after: 90, line: 288 },
}));

/* ═══════════════════════════════════════════════════════════════════ */
/* ── Gate ───────────────────────────────────────────────────────────────
   adapt-scan.js leaves a TODO string wherever the scan could not supply an
   answer. Those are judgements — retention, authorisation, costs, the board
   narrative — and a plausible default for any of them is a number a client's
   board would read as a finding. Callers must run this before build(); the
   CLI prints the list, the server returns it as a 409. */
function validate(scan) {
  const todos = [];
  (function walk(node, path) {
    if (typeof node === 'string') { if (node.startsWith('TODO')) todos.push({ path, text: node.replace(/^TODO — /, '') }); return; }
    if (Array.isArray(node)) return node.forEach((v, i) => walk(v, `${path}[${i}]`));
    if (node && typeof node === 'object') Object.entries(node).forEach(([k, v]) => walk(v, path ? `${path}.${k}` : k));
  })(scan, '');

  /* The report prints the components as a table with the index as its total
     row, so a hand-edit that leaves them disagreeing is visible to the
     client. */
  const rec = reconcile(scan.assessment || {});
  return {
    ok: todos.length === 0 && rec.ok,
    todos,
    reconciles: rec.ok,
    reconcile: rec,
  };
}

/* Returns { buffer, sections }. `opts.tocPages` maps a section title to the
   page it landed on; without it the contents page renders unnumbered, which
   is deliberate — a stale page number is worse than no page number. */
const DRAFT_MARK = '[TO BE COMPLETED]';

/* Collect every TODO and swap it for the marker, leaving the rest untouched.
   Done on a copy of the input rather than at each of the renderer's many call
   sites, so a field added later cannot slip through unmarked. */
function draftify(node, outstanding, path = '') {
  if (typeof node === 'string') {
    if (node.startsWith('TODO')) {
      outstanding.push({ path, why: node.replace(/^TODO — /, '') });
      return DRAFT_MARK;
    }
    return node;
  }
  if (Array.isArray(node)) return node.map((v, i) => draftify(v, outstanding, `${path}[${i}]`));
  if (node && typeof node === 'object') {
    const o = {};
    for (const [k, v] of Object.entries(node)) o[k] = draftify(v, outstanding, path ? `${path}.${k}` : k);
    return o;
  }
  return node;
}

async function build(scan, opts = {}) {
  const TOC_PAGES = opts.tocPages || null;

  /* Draft: build before the profile is complete, with every unanswered field
     marked. The document says so in the header, the classification, a banner
     on page one and a closing section — a draft that can be mistaken for a
     deliverable is worse than no draft at all. */
  const DRAFT = !!opts.draft;
  const OUTSTANDING = [];
  if (DRAFT) {
    scan = draftify(scan, OUTSTANDING);
    scan.client = Object.assign({}, scan.client, {
      classification: 'DRAFT — NOT FOR ISSUE',
    });
  }
  const c = scan.client;
  const a = scan.assessment;
  const s = scan.scope;
  /* A MEDIUM index printed in the same red as a HIGH one overstates the finding.
     The band decides the colour everywhere the index is shown. */
  const BAND_TONE = { HIGH: RED, MEDIUM: AMBER, LOW: GREEN };
  const bandTone = BAND_TONE[a.band] || RED;
  /* In a draft the retention period may not have been stated yet, in which
     case the horizon and the overrun are not computable. Printing NaN into a
     board document is not an option, and neither is picking a number. */
  const retentionKnown = typeof c.data_retention_years === 'number' &&
                         isFinite(c.data_retention_years);
  const horizon = retentionKnown ? a.assessment_year + c.data_retention_years : null;
  const overrun = retentionKnown ? horizon - a.crqc_estimate : null;
  const K = [];

  /* Sections register themselves as they are emitted, so the contents page and the
     headings cannot drift apart. Page numbers come from an optional sidecar written
     by make-pdf.js; without it the contents renders unnumbered rather than wrong. */
  const SECTIONS = [];
  function open_(kicker, title) {
    SECTIONS.push({ kicker, title });
    K.push(KICKER(kicker), H1(title), RULE_P());
  }

  /* ── 1. Cover ──────────────────────────────────────────────────────── */
  K.push(
    gap(1500),
    p([t('CipherQ', { size: 50, bold: true, color: AMBER })], { after: 40 }),
    p([t('Post-quantum cryptographic intelligence', { size: 18, color: MUTED, caps: true, spacing: 50 })], { after: 1000 }),
    p([t('Quantum Exposure', { size: 46, bold: true })], { after: 0 }),
    p([t('Assessment', { size: 46, bold: true })], { after: 300 }),
    p([t(c.name, { size: 26, color: MUTED })], { after: 60 }),
    p([t(c.domain, { size: 20, color: MUTED, mono: true })], { after: 800 }),
  );

  K.push(tbl([2340, 2340, 2340, 2340], [
    new TableRow({ children: [
      cell('Issued',        { width: 2340, caps: true, size: 14, color: MUTED, bold: true }),
      cell('Classification',{ width: 2340, caps: true, size: 14, color: MUTED, bold: true }),
      cell('Authorisation', { width: 2340, caps: true, size: 14, color: MUTED, bold: true }),
      cell('Exposure index',{ width: 2340, caps: true, size: 14, color: MUTED, bold: true }),
    ]}),
    new TableRow({ children: [
      cell(c.date_issued,      { width: 2340, size: 18 }),
      cell(c.classification,   { width: 2340, size: 18 }),
      cell(a.authorisation,    { width: 2340, size: 16, mono: true }),
      cell(`${a.qei} / ${a.qei_max || 100}`,   { width: 2340, size: 22, bold: true, color: bandTone }),
    ]}),
  ]));

  K.push(new Paragraph({ children: [new PageBreak()] }));
  const TOC_AT = K.length;

  /* ── 2. Board summary ──────────────────────────────────────────────── */
  const b = scan.board;
  const inv = scan.projection.investment.filter(x => x.qei_delta > 0);
  const invLow = inv.reduce((s, x) => s + x.low, 0);
  const invHigh = inv.reduce((s, x) => s + x.high, 0);

  open_('For the Board', 'Board summary');

  /* Four figures a board can hold in its head */
  K.push(tbl([2340, 2340, 2340, 2340], [
    new TableRow({ children: [
      cell([
        p([t(`${a.qei}`, { size: 36, bold: true, color: bandTone })], { after: 0, align: AlignmentType.CENTER }),
        p([t(a.band, { size: 15, bold: true, color: bandTone, caps: true, spacing: 60 })], { after: 15, align: AlignmentType.CENTER }),
        p([t('exposure index', { size: 13, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 2340 }),
      cell([
        p([t(retentionKnown ? `${overrun}` : '—', { size: 36, bold: true, color: retentionKnown ? RED : MUTED })], { after: 15, align: AlignmentType.CENTER }),
        p([t(retentionKnown ? 'years unprotected' : 'retention not stated', { size: 13, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 2340 }),
      cell([
        p([t(`${scan.kex.hosts_with_pq_kex} / ${s.hosts_reachable}`, { size: 36, bold: true, color: RED })], { after: 15, align: AlignmentType.CENTER }),
        p([t('hosts quantum-safe', { size: 13, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 2340 }),
      cell([
        p([t(`${scan.projection.qei_after_all}`, { size: 36, bold: true, color: GREEN })], { after: 15, align: AlignmentType.CENTER }),
        p([t('index if you act', { size: 13, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 2340 }),
    ]}),
  ]));

  K.push(gap(200));

  /* Strong / exposed, side by side */
  K.push(tbl([4680, 4680], [
    new TableRow({ children: [
      cell([
        p([t('Where you are strong', { size: 16, bold: true, color: GREEN, caps: true, spacing: 40 })], { after: 110 }),
        p(b.position_good, { size: 18, after: 0 }),
      ], { width: 4680 }),
      cell([
        p([t('Where you are exposed', { size: 16, bold: true, color: RED, caps: true, spacing: 40 })], { after: 110 }),
        p(b.position_bad, { size: 18, after: 0 }),
      ], { width: 4680 }),
    ]}),
  ]));

  K.push(gap(200));

  /* The consequence */
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t(`Data recorded today is confidential until ${horizon}. The cryptography protecting it is expected to fail in ${a.crqc_estimate}.`, { size: 21, bold: true })], { after: 110 }),
    p(b.exposure_statement, { size: 18, after: 0 }),
  ], { width: W, fill: WASH })]})]));

  K.push(gap(200));

  K.push(new Paragraph({ children: [t('What we are asking for', { size: 25, bold: true })], heading: HeadingLevel.HEADING_2, spacing: { before: 160, after: 110 } }));
  K.push(p([t(b.ask_headline, { size: 21, bold: true, color: AMBER })], { after: 110 }));
  K.push(p(b.ask_detail, { after: 200 }));

  const bw = [4400, 1900, 3060];
  K.push(tbl(bw, [
    head(bw, ['Band', 'Window', 'Indicative cost']),
    ...inv.map(x => new TableRow({ children: [
      cell(x.band, { width: bw[0], bold: true }),
      cell(x.window, { width: bw[1], size: 17, mono: true }),
      cell(`${money(x.low)} – ${money(x.high)}`, { width: bw[2], size: 17, mono: true }),
    ]})),
    new TableRow({ children: [
      cell('Total requested', { width: bw[0], bold: true, caps: true, size: 15 }),
      cell('6 months', { width: bw[1], bold: true, size: 17, mono: true }),
      cell(`${money(invLow)} – ${money(invHigh)}`, { width: bw[2], bold: true, size: 19, mono: true, color: AMBER }),
    ]}),
  ]));

  K.push(gap(150));
  K.push(p([t('If approved: ', { size: 18, bold: true, color: GREEN }), t(b.outcome, { size: 18 })], { after: 0 }));

  K.push(gap(240));

  /* Decision — the only boxed element in the report. The cost of not deciding
     sits inside the box, because that is the thing a deferral has to answer. */
  K.push(tbl([W], [new TableRow({ cantSplit: true, children: [cell([
    p([t('Decision required', { size: 15, bold: true, color: AMBER, caps: true, spacing: 60 })], { after: 110 }),
    p([t(b.decision, { size: 22, bold: true })], { after: 90 }),
    p([t(b.if_deferred, { size: 17, color: MUTED })], { after: 60 }),
    p([t(b.decision_owner, { size: 17, color: MUTED })], { after: 0 }),
  ], { width: W })]})], { boxed: true }));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 3. The exposure window (signature section) ─────────────────────── */
  open_('Section 02', 'Your exposure window');

  K.push(p([
    t('This assessment turns on one relationship: how long your data must stay confidential, measured against when the cryptography protecting it is expected to fail.', { size: 22 }),
  ], { after: 240 }));

  K.push(tbl([3120, 3120, 3120], [
    new TableRow({ children: [
      cell([
        p([t(String(a.assessment_year), { size: 38, bold: true })], { after: 20, align: AlignmentType.CENTER }),
        p([t('assessed', { size: 14, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 3120 }),
      cell([
        p([t(String(a.crqc_estimate), { size: 38, bold: true, color: AMBER })], { after: 20, align: AlignmentType.CENTER }),
        p([t('cryptography fails', { size: 14, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 3120 }),
      cell([
        p([t(String(horizon), { size: 38, bold: true, color: RED })], { after: 20, align: AlignmentType.CENTER }),
        p([t('data still confidential', { size: 14, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
      ], { width: 3120 }),
    ]}),
  ]));

  K.push(gap(260));
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t(retentionKnown
      ? `${overrun} years of unprotected confidentiality`
      : 'Exposure window not yet quantifiable', { size: 21, bold: true, color: retentionKnown ? RED : MUTED })], { after: 110 }),
    p(retentionKnown
      ? `${c.retention_basis}. Material intercepted today therefore remains confidential until ${horizon} — ${overrun} years beyond the point at which the cryptography protecting it in transit is expected to be broken.`
      : `The retention period has not been stated, so the exposure window cannot be computed. It is the single largest determinant of this assessment — worth 20 index points — and until it is attested the index is scored out of ${a.qei_max} rather than 100.`, { after: 110 }),
    p('The consequence is that the exposure is not in the future. Traffic captured now, stored, and decrypted later is compromised from the moment it is recorded. Enabling post-quantum key establishment does not repair material already intercepted; it stops the window widening.', { after: 0 }),
  ], { width: W, fill: WASH })]})]));

  K.push(gap(280));
  K.push(H2('How the index is composed'));
  K.push(p([t('Every point is attributable to an observation or a policy rule. No component is assigned by inference, and none is produced by a language model.', { color: MUTED, size: 19 })], { after: 180 }));

  const cw = [2680, 1420, 5260];
  K.push(tbl(cw, [
    head(cw, ['Dimension', 'Points', 'Basis']),
    ...a.components.map(x => new TableRow({ children: [
      cell(x.dimension, { width: cw[0], bold: true }),
      cell(`${x.points} / ${x.max}`, { width: cw[1], bold: true, mono: true,
            color: x.points / x.max > 0.7 ? RED : x.points / x.max > 0.45 ? AMBER : MUTED }),
      cell(x.note, { width: cw[2], size: 17 }),
    ]})),
    new TableRow({ children: [
      cell('Quantum Exposure Index', { width: cw[0], bold: true, caps: true, size: 15 }),
      cell(`${a.qei} / ${a.qei_max || 100}`, { width: cw[1], bold: true, size: 20, color: bandTone, mono: true }),
      cell(`Band: ${a.band}`, { width: cw[2], bold: true }),
    ]}),
  ]));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 3. Assurance register (signature section) ─────────────────────── */
  open_('Section 03', 'What we verified');

  K.push(p('An assessment is only as good as its evidence. This register states, for each area, whether the finding was directly verified, inferred from client-supplied information, or outside scope. Nothing in this report is presented as verified unless it was observed.'));
  K.push(gap(160));

  const aw = [2900, 3100, 1780, 1580];
  K.push(tbl(aw, [
    head(aw, ['Area', 'Method', 'Status', 'Confidence']),
    ...scan.assurance.map(x => new TableRow({ children: [
      cell(x.area, { width: aw[0], bold: true }),
      cell(x.method, { width: aw[1], size: 17 }),
      cell(x.status, { width: aw[2], bold: true,
            color: x.status === 'Verified' ? GREEN : x.status === 'Inferred' ? AMBER : MUTED }),
      cell(x.confidence, { width: aw[3], size: 17, color: MUTED }),
    ]})),
  ]));

  K.push(gap(260));
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t('Why this matters', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })], { after: 90 }),
    p(`Key-exchange capability cannot be determined from a certificate, a banner, or a single handshake. CipherQ performed ${s.handshakes_performed} handshakes across ${s.hosts_reachable} hosts with progressively restricted group sets, to establish what each host will actually negotiate rather than what it advertises. Where a report cannot distinguish these, its post-quantum conclusions are inference.`, { after: 0 }),
  ], { width: W, fill: WASH })]})]));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 4. Exposure classes ───────────────────────────────────────────── */
  open_('Section 04', 'Exposures by threat model');

  K.push(p('Post-quantum exposures are not interchangeable. Grouping them by threat model rather than severity keeps the distinction that matters: what the adversary actually does. Two of these classes turn on cryptography being broken; one turns on credentials that were never broken at all, only recovered.'));
  K.push(gap(180));

  const clw = [1980, 4200, 1590, 1590];
  K.push(tbl(clw, [
    head(clw, ['Class', 'Threat model', 'Exposures', 'Index points']),
    ...CLASSES.map(cl => {
      const set = scan.exposures.filter(e => e.class === cl);
      const pts = set.reduce((n, e) => n + e.score_contribution, 0);
      const desc = {
        A: 'Retrospective. Material transmitted today is compromised when quantum capability arrives. Confidentiality.',
        B: 'Forward. Risk begins when quantum capability arrives; historic material is unaffected. Integrity and authenticity.',
        C: 'Present-day. Unrelated to quantum computing, but bears on the same programme and the same estate.',
        D: 'Operational. The adversary neither decrypts nor forges — they present genuine credentials and authenticate. Access and non-repudiation.',
      }[cl];
      return new TableRow({ children: [
        cell(CLASS_NAME[cl], { width: clw[0], bold: true, color: CLASS_TONE[cl], size: 17 }),
        cell(desc, { width: clw[1], size: 17 }),
        cell(String(set.length), { width: clw[2], bold: true, align: AlignmentType.CENTER }),
        cell(String(pts), { width: clw[3], bold: true, mono: true, align: AlignmentType.CENTER,
              color: cl === 'A' ? RED : INK }),
      ]});
    }),
  ]));

  K.push(gap(240));
  K.push(p([t('Class A carries the priority. Delay there increases the volume of compromised material, and nothing retires it: traffic already captured cannot be un-captured.', { bold: true })], { after: 130 }));
  K.push(p([t('Class D is the closest to it and the distinction is worth stating precisely. Delay increases the volume of harvested authentication material in the same way — but unlike Class A, rotation retires it. A credential recovered from a handshake captured five years ago is worthless if the key it authenticates has since been re-issued. That makes credential lifetime a control in Class D where it is no control at all in Class A, and it is why the operator-access track is scoped around rotation and gateway placement rather than around cryptography alone.', { color: MUTED })], { after: 130 }));
  K.push(p([t('Class C items appear early in the sequence and cost tables because they take days rather than weeks and are carried by a different team. Speed of closure is not precedence: nothing in Class C reduces retrospective exposure, and neither the Class A nor the Class D track should wait on it.', { color: MUTED })], { after: 0 }));

  /* ── 5. Each exposure ──────────────────────────────────────────────── */
  CLASSES.forEach(cl => {
    const set = scan.exposures.filter(e => e.class === cl);
    if (!set.length) return;

    K.push(new Paragraph({ children: [new PageBreak()] }));
    open_(CLASS_NAME[cl], CLASS_LABEL[cl]);

    set.forEach((e, i) => {
      if (i > 0) K.push(gap(360));

      K.push(tbl([1080, 6120, 1080, 1080], [
        new TableRow({ children: [
          cell(e.ref, { width: 1080, bold: true, size: 22, color: CLASS_TONE[cl], mono: true }),
          cell(e.title, { width: 6120, bold: true, size: 21 }),
          cell([
            p([t(String(e.hosts_affected), { size: 20, bold: true })], { after: 10, align: AlignmentType.CENTER }),
            p([t('hosts', { size: 13, color: MUTED, caps: true })], { after: 0, align: AlignmentType.CENTER }),
          ], { width: 1080 }),
          cell([
            p([t('+' + e.score_contribution, { size: 20, bold: true, color: CLASS_TONE[cl], mono: true })], { after: 10, align: AlignmentType.CENTER }),
            p([t('index', { size: 13, color: MUTED, caps: true })], { after: 0, align: AlignmentType.CENTER }),
          ], { width: 1080 }),
        ]}),
      ]));

      K.push(gap(150));
      K.push(p([t('OBSERVED   ', { size: 14, bold: true, color: AMBER, spacing: 40 }), t(e.observation)]));
      K.push(p([t('MATTERS BECAUSE   ', { size: 14, bold: true, color: AMBER, spacing: 40 }), t(e.why_it_matters)]));
      K.push(p([t('ACTION   ', { size: 14, bold: true, color: AMBER, spacing: 40 }), t(e.action)]));

      K.push(gap(120));
      const ew = [4680, 4680];
      K.push(tbl(ew, [
        head(ew, ['Evidence', 'Value']),
        /* qea-input emits `label`; hand-edited scan files and adapt-scan.js
           have used `item`. Reading only one printed the string "undefined"
           in the left column of every evidence table in the report. */
        ...e.evidence.map(v => new TableRow({ children: [
          cell(v.item || v.label || '', { width: ew[0], size: 17, color: MUTED }),
          cell(v.value, { width: ew[1], size: 17, bold: true, mono: true }),
        ]})),
      ], { boxed: false }));
    });
  });

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 6. Sequence ───────────────────────────────────────────────────── */
  open_('Section 05', 'Sequence of work');
  /* The track count is not fixed: an estate with no reachable operator
     surface has no Class D track, and saying "two tracks" over three rows
     is the kind of small wrongness a reader notices. */
  const trackCount = new Set(scan.sequence.map(x => x.track || '—')).size;
  const trackWord = ['no', 'One track', 'Two tracks', 'Three tracks', 'Four tracks'][trackCount] || `${trackCount} tracks`;
  K.push(p(`${trackWord}, owned by different teams and run concurrently. None waits on another. Within a track, steps are ordered by dependency rather than by effort; steps showing no dependency can begin immediately.`));
  K.push(gap(160));

  const sw = [700, 4700, 1560, 1200, 1200];
  const TRACK_TONE = {
    'Class A — key establishment': RED,
    'Class D — operator access': BRONZE,
    'Class C — present-day hygiene': MUTED,
    'Inventory': MUTED,
  };
  const trackRow = name => new TableRow({ children: [cell([
    p([t(name, { size: 15, bold: true, color: TRACK_TONE[name] || MUTED, caps: true, spacing: 60 })], { after: 0 }),
  ], { width: sw.reduce((a, b) => a + b, 0), span: 5, fill: WASH })]});

  const seqRows = [];
  let lastTrack = null;
  scan.sequence.forEach(x => {
    const tr = x.track || '—';
    if (tr !== lastTrack) { seqRows.push(trackRow(tr)); lastTrack = tr; }
    seqRows.push(new TableRow({ children: [
      cell(String(x.step), { width: sw[0], bold: true, color: AMBER, align: AlignmentType.CENTER, mono: true }),
      cell(x.action, { width: sw[1], size: 17 }),
      cell(x.depends_on, { width: sw[2], size: 16, color: MUTED }),
      cell(x.effort, { width: sw[3], size: 16 }),
      cell(x.owner, { width: sw[4], size: 16, color: MUTED }),
    ]}));
  });

  K.push(tbl(sw, [head(sw, ['', 'Action', 'Depends on', 'Effort', 'Owner']), ...seqRows]));
  K.push(gap(240));
  K.push(p([t('The critical path is the Class A track. It is longer, it is owned by Security Engineering, and it is the only track that changes the confidentiality of material already in transit. Where an operator-access track is present it runs alongside rather than behind: its first step is the same hybrid key establishment work applied to the management plane, and its remaining steps are firewall and lifecycle changes that need no cryptographic decision at all. The hygiene track is quick and cheap, and is listed last for that reason — not because it matters less to a browser, but because it bears on neither.', { color: MUTED })], { after: 0 }));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 7. Projection ─────────────────────────────────────────────────── */
  open_('Section 06', 'What changes if you act');
  const pr = scan.projection;
  const hasAccess = typeof pr.qei_after_access === 'number'
    && pr.qei_after_access !== pr.qei_after_kex;

  K.push(p(`Modelled by re-running the scoring engine against the target configuration. The same rules, applied to the estate as it would stand after each band of work. The bands run concurrently; the windows overlap rather than follow one another${hasAccess ? ', and the operator-access track shares its first step with key establishment' : ''}.`));
  K.push(gap(200));

  /* Stages are built rather than fixed, so an estate with no reachable
     operator surface does not get a column that says nothing. */
  const stages = [
    { v: pr.qei_now, label: 'today', tone: bandTone },
    { v: pr.qei_after_kex, label: 'after key establishment', tone: AMBER },
    ...(hasAccess ? [{ v: pr.qei_after_access, label: 'after operator access', tone: BRONZE }] : []),
    { v: pr.qei_after_all, label: 'after all tracks', tone: GREEN },
  ];
  const stw = Math.floor(W / stages.length);
  K.push(tbl(stages.map(() => stw), [
    new TableRow({ children: stages.map(x => cell([
      p([t(String(x.v), { size: 40, bold: true, color: x.tone })], { after: 15, align: AlignmentType.CENTER }),
      p([t(x.label, { size: 14, color: MUTED, caps: true, spacing: 40 })], { after: 0, align: AlignmentType.CENTER }),
    ], { width: stw })) }),
  ]));

  K.push(gap(280));
  const iw = [3200, 1700, 2400, 2060];
  K.push(tbl(iw, [
    head(iw, ['Band of work', 'Window', 'Indicative cost', 'Index reduction']),
    ...pr.investment.map(x => new TableRow({ children: [
      cell(x.band, { width: iw[0], bold: true }),
      cell(x.window, { width: iw[1], size: 17 }),
      cell(`${money(x.low)} – ${money(x.high)}`, { width: iw[2], mono: true, size: 17 }),
      cell(x.qei_delta ? `−${x.qei_delta}` : 'Enables 2028 position', {
        width: iw[3], bold: true, mono: !!x.qei_delta, color: x.qei_delta ? GREEN : MUTED, size: 17 }),
    ]})),
  ]));

  K.push(gap(240));
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t('Why it does not reach zero', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })], { after: 90 }),
    p(pr.residual_explanation, { after: 0 }),
  ], { width: W, fill: WASH })]})]));

  K.push(gap(320));
  K.push(H2('How completion is verified'));
  K.push(p([t('Each measure is re-tested by the same method that produced the baseline. Nothing is closed on assertion.', { color: MUTED, size: 19 })], { after: 170 }));

  const vw = [3600, 1800, 1800, 2160];
  K.push(tbl(vw, [
    head(vw, ['Measure', 'Today', 'Target', 'Verified by']),
    /* Same key mismatch as the evidence tables: qea-input emits `today`,
       this read `now`, and the Today column printed "undefined" on every
       row of every report. Accept both. */
    ...scan.verification.map(x => new TableRow({ children: [
      cell(x.measure, { width: vw[0], size: 17 }),
      cell(x.now !== undefined ? x.now : (x.today !== undefined ? x.today : ''),
           { width: vw[1], size: 17, color: MUTED, mono: true }),
      cell(x.target, { width: vw[2], size: 17, bold: true, color: GREEN, mono: true }),
      cell(x.verified_by, { width: vw[3], size: 16, color: MUTED }),
    ]})),
  ]));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 8. Regulatory ─────────────────────────────────────────────────── */
  open_('Section 07', 'Regulatory position');
  K.push(p([t('The operative deadline is not 2035. The National Cyber Security Centre expects cryptographic discovery to be complete and a migration plan drafted by 2028 — two years from this assessment.', { size: 21 })], { after: 200 }));

  const rw = [1300, 3060, 5000];
  K.push(tbl(rw, [
    head(rw, ['Year', 'Milestone', 'Requirement']),
    ...[
      ['2024', 'NIST FIPS 203/204/205', 'Post-quantum standards finalised and available for production use.'],
      ['2026', 'This assessment', 'Hybrid key establishment widely deployed by browsers and major providers. Discovery should be underway.'],
      ['2028', 'NCSC — discovery complete', 'A full inventory of cryptographic dependencies and a drafted migration plan. The binding near-term expectation.'],
      ['2031', 'NCSC — high priority migrated', 'Highest-priority systems migrated; infrastructure prepared for full transition.'],
      ['2033', 'CRQC estimate', 'Working assumption for when classical key establishment fails. An estimate, and treated as one.'],
      ['2035', 'NCSC — migration complete', 'All systems, services and products migrated.'],
    ].map(([y, m, r], i) => new TableRow({ children: [
      cell(y, { width: rw[0], bold: true, mono: true, color: i === 1 ? AMBER : i === 2 ? RED : INK }),
      cell(m, { width: rw[1], bold: i === 2, size: 17 }),
      cell(r, { width: rw[2], size: 17 }),
    ]})),
  ]));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 9. Method ─────────────────────────────────────────────────────── */
  open_('Section 08', 'Method');

  K.push(H2('What was examined'));
  K.push(p(`The externally observable cryptographic surface of ${c.domain}. ${s.hosts_discovered} host names were enumerated from ${s.discovery_method}; ${s.hosts_probed} were probed and ${s.hosts_reachable} completed a TLS handshake between ${scan.assessment.scan_window}.`));

  K.push(H2('How'));
  K.push(...bullets([
    'Surface enumeration from Certificate Transparency logs and public DNS. This reads records published by third parties and reaches no client infrastructure, so it surfaces hosts absent from internally maintained inventories.',
    `Differential key-exchange probing. ${s.handshakes_performed} handshakes across ${s.hosts_reachable} hosts, each with progressively restricted group sets, establishing negotiated capability rather than advertised preference.`,
    'Certificate chain retrieval and validation, including subject matching against the queried name.',
    'HTTP response inspection for transport-security, framing and content-type controls.',
    'Deterministic scoring. Each exposure contributes a fixed number of index points derived from algorithm properties, observed configuration, declared data lifetime and exposure surface. The same estate scores identically on every run.',
  ]));

  K.push(H2('What was not examined'));
  K.push(p('Stated precisely. A reader is entitled to know the boundary of the evidence.'));
  K.push(...bullets([
    'Internal infrastructure, endpoint cryptography, document management and application-layer cryptography. This is an external assessment.',
    'Data at rest — database, disk and object-store encryption. Where retention is long, at-rest cryptography warrants separate examination.',
    'Non-TLS services on the same hosts, including SSH and mail submission.',
    'Supplier cryptographic posture. Third-party exposure is assessed separately.',
    'Hosts that did not respond during the scan window. Recorded, not assessed.',
  ]));

  K.push(new Paragraph({ children: [new PageBreak()] }));
  open_('Section 08 · continued', 'Terms');
  const dw = [2500, 6860];
  K.push(tbl(dw, [
    ...[
      ['Retrospective exposure', 'Material transmitted today is compromised once quantum capability arrives. Applies to key establishment. Delay increases the volume of compromised material.'],
      ['Forward exposure', 'Risk begins when quantum capability arrives; material already transmitted is unaffected. Applies to signatures.'],
      ['Operational exposure', 'An adversary authenticates using genuine credential material recovered from recorded key establishment, rather than decrypting traffic or forging an artifact. Nothing is anomalous: the credential was issued by the organisation and is still trusted, and the audit trail records an authorised operator. Rotation retires it, which is the practical difference from retrospective exposure. Also referred to as Deploy Now, Exploit Later.'],
      ['Crypto-agility constraint', 'Whether an asset can accept new cryptography at all — field-upgradable, firmware-locked, certification-locked or hardware-locked. Not observable over the wire and not assessed here. It is the principal determinant of operational exposure in estates with long equipment lifecycles.'],
      ['CRQC', 'Cryptographically relevant quantum computer. Sufficient stable logical qubits to run Shor\'s algorithm against production key sizes. The 2033 figure is an estimate and is configurable.'],
      ['Hybrid key establishment', 'A construction combining classical and post-quantum mechanisms, such as X25519MLKEM768. Security holds if either component holds, so deployment carries no reduction in classical security.'],
      ['ML-KEM', 'Module-Lattice Key Encapsulation Mechanism, NIST FIPS 203.'],
      ['Quantum Exposure Index', 'CipherQ\'s composite score across seven weighted dimensions. Dimensions that could not be assessed are removed from the denominator rather than scored zero, so the maximum shown is not always 100. Every point is attributable to an observation or a rule.'],
    ].map(([k, v]) => new TableRow({ children: [
      cell(k, { width: dw[0], bold: true, size: 17 }),
      cell(v, { width: dw[1], size: 17 }),
    ]})),
  ]));

  K.push(new Paragraph({ children: [new PageBreak()] }));

  /* ── 10. Observation log ───────────────────────────────────────────── */
  open_('Appendix', 'Observation log');

  /* Optional observations are omitted when absent rather than printed as
     zero. An HTTP scan that was never run is not an estate with no HTTP
     problems, and the assurance register already records it as out of
     scope. */
  const ow = [5600, 3760];
  const H = scan.http || {};
  const proto = (scan.tls && scan.tls.protocols) || {};
  const obs = [
    ['Host names discovered', s.hosts_discovered],
    ['Hosts probed', s.hosts_probed],
    ['Hosts completing a TLS handshake', s.hosts_reachable],
    ['Handshakes performed', s.handshakes_performed],
    ...Object.entries(proto).map(([k, v]) => [`Negotiating ${k.replace(/^TLSv/, 'TLS ')}`, v]),
    ['Hosts negotiating a hybrid group', scan.kex.hosts_with_pq_kex],
    ['Classical groups observed', (scan.kex.groups_observed || []).join(', ')],
    ['Certificates examined', scan.certificates.total],
    ['Certificates with post-quantum signatures', scan.certificates.pq_signature_count],
    ['Certificates expiring within 90 days', scan.certificates.expiring_90d],
    ['Certificate subject mismatches', scan.certificates.sni_mismatches],
    ['Hosts without HSTS', H.hsts_absent],
    ['Hosts on the HSTS preload list', H.hsts_preloaded],
    ['Hosts without Content-Security-Policy', H.csp_absent],
    ['Hosts serving mixed content', H.mixed_content_hosts],
    ['Externally reachable non-production hosts', scan.surface.dev_or_staging_reachable],
    ['Dormant DNS records', scan.surface.dormant_dns_records],
    ...(scan.dnel ? [
      ['Hosts exposing an operator-authentication surface', scan.dnel.operator_surface_hosts],
      ['Operator surface classes reachable', scan.dnel.classes.map(x => `${x.label} (${x.hosts})`).join(', ')],
      ['SSH hosts probed', scan.dnel.ssh_scanned],
      ['SSH hosts without hybrid key exchange', scan.dnel.ssh_classical_kex],
      ['Cleartext administration protocol reachable', scan.dnel.cleartext_admin ? 'Yes' : 'No'],
      ['Operator credentials valid beyond the CRQC estimate', scan.dnel.credentials_outliving_horizon],
    ] : []),
  ].filter(([, v]) => v !== undefined && v !== null && v !== '')
   .map(([k, v]) => [k, String(v)]);
  K.push(tbl(ow, [
    head(ow, ['Observation', 'Value']),
    ...obs.map(([k, v]) => new TableRow({ children: [
      cell(k, { width: ow[0], size: 17 }),
      cell(v, { width: ow[1], size: 17, bold: true, mono: true }),
    ]})),
  ]));

  K.push(gap(300));
  K.push(H2('Key-exchange probe detail'));
  K.push(p(scan.kex.downgrade_findings));

  K.push(gap(240));
  K.push(H2('Certificate authorities'));
  const caw = [5600, 3760];
  K.push(tbl(caw, [
    head(caw, ['Authority', 'Certificates']),
    ...Object.entries(scan.certificates.issuers).map(([k, v]) => new TableRow({ children: [
      cell(k, { width: caw[0], size: 17 }),
      cell(String(v), { width: caw[1], size: 17, bold: true, mono: true }),
    ]})),
  ]));

  /* Only if you actually grade. Printing an all-zero grade row would read as
     five failing hosts. */
  if (H.grade_distribution) {
    K.push(gap(240));
    K.push(H2('HTTP security grades'));
    const gw = [1872, 1872, 1872, 1872, 1872];
    K.push(tbl(gw, [
      head(gw, ['A', 'B', 'C', 'D', 'F']),
      new TableRow({ children: ['A', 'B', 'C', 'D', 'F'].map((g, i) =>
        cell(String(H.grade_distribution[g] || 0), {
          width: gw[i], bold: true, size: 22, mono: true, align: AlignmentType.CENTER,
          color: g === 'A' ? GREEN : (g === 'D' || g === 'F') ? RED : INK })) }),
    ]));
  }

  K.push(gap(320));
  K.push(H2('Standards referenced'));
  K.push(...bullets([
    'NCSC, Timelines for migration to post-quantum cryptography — the 2028, 2031 and 2035 milestones.',
    'NIST FIPS 203 — Module-Lattice Key Encapsulation Mechanism.',
    'NIST FIPS 204 — Module-Lattice Digital Signature Algorithm.',
    'NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard.',
    'CycloneDX / ECMA-424 — Cryptography Bill of Materials.',
  ]));

  K.push(gap(300));
  K.push(tbl([W], [new TableRow({ children: [cell([
    p([t('About this assessment', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })], { after: 90 }),
    p('Produced by CipherQ. The scoring engine is deterministic: identical input produces identical output, and every index point traces to a stated observation or rule. Where a conclusion rests on client-supplied information rather than direct observation, the assurance register says so.', { after: 100 }),
    p([t('cipherq.co', { bold: true }), t('   ·   info@cipherq.co')], { after: 0 }),
  ], { width: W, fill: WASH })]})]));

  /* ── Contents ──────────────────────────────────────────────────────────
     Built last, from what was actually emitted, and spliced in after the cover.
     A live Word TOC field was the obvious choice and is the wrong one here: the
     deliverable is a PDF, and headless converters leave the field unpopulated —
     the client would receive a blank contents page. */
  /* Everything still outstanding, named with the reason it matters, so the
     draft is also the worklist for finishing it. */
  if (DRAFT) {
    open_('Before issue', 'Outstanding');
    K.push(p('This document is a draft. Every field marked ' + DRAFT_MARK + ' is a judgement the scan cannot make, and each one below must be answered before the report is issued to a client.', { after: 140 }));
    if (!OUTSTANDING.length) {
      K.push(p('Nothing outstanding.', { after: 140 }));
    } else {
      K.push(tbl([2900, 6460], [
        new TableRow({ children: [
          cell([p([t('Field', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })])], { width: 2900, fill: WASH }),
          cell([p([t('What is needed', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })])], { width: 6460, fill: WASH }),
        ]}),
        ...OUTSTANDING.map(o => new TableRow({ children: [
          cell([p([t(o.path, { size: 17, bold: true })])], { width: 2900 }),
          cell([p([t(o.why, { size: 17, color: MUTED })])], { width: 6460 }),
        ]})),
      ]));
      K.push(gap(160));
      K.push(p([t(`${OUTSTANDING.length} field${OUTSTANDING.length === 1 ? '' : 's'} outstanding.`, { bold: true, color: RED })], { after: 140 }));
    }
    if (!scan.assessment || scan.assessment.complete === false) {
      K.push(p([t('The index is scored out of ' + ((scan.assessment && scan.assessment.qei_max) || 100) + ', not 100: dimensions that could not be assessed are removed from the denominator rather than scored zero. Answering the outstanding fields — the retention period above all — will change both the figure and its maximum.', { color: MUTED })], { after: 140 }));
    }
  }

  const numbered = TOC_PAGES && SECTIONS.every(x => TOC_PAGES[x.title]);
  const tocRows = SECTIONS.map(x => new TableRow({ children: [
    cell(x.kicker, { width: 2200, size: 14, caps: true, color: MUTED, bold: true }),
    cell(x.title,  { width: numbered ? 6360 : 7160, size: 19, bold: true }),
    ...(numbered ? [cell(String(TOC_PAGES[x.title]), {
      width: 800, size: 19, bold: true, color: AMBER, mono: true, align: AlignmentType.RIGHT })] : []),
  ]}));

  const TOC = [
    KICKER('Contents'),
    H1('Quantum Exposure Assessment'),
    RULE_P(),
    p([t(`${c.name} · ${c.domain}`, { size: 20, color: MUTED })], { after: 260 }),
    tbl(numbered ? [2200, 6360, 800] : [2200, 7160], tocRows),
    gap(300),
    tbl([W], [new TableRow({ children: [cell([
      p([t('How to read this report', { size: 16, bold: true, color: AMBER, caps: true, spacing: 40 })], { after: 90 }),
      p('Exposures are grouped by threat model rather than by severity, because what the adversary does differs by class. Class A is retrospective: material transmitted today is compromised once quantum capability arrives, so delay increases the volume at risk and nothing retires it. Class D is operational: the adversary presents genuine credentials rather than decrypting or forging anything, so there is no anomaly to detect — but unlike Class A, rotation retires the exposure. Class B and Class C carry neither property. Where the report sequences Class C work early, it is because those items take days and a different team carries them — not because they rank above Class A.', { size: 18, after: 0 }),
    ], { width: W, fill: WASH })]})]),
    new Paragraph({ children: [new PageBreak()] }),
  ];
  K.splice(TOC_AT, 0, ...TOC);

  /* ═══════════════════════════════════════════════════════════════════ */
  const doc = new Document({
    creator: 'CipherQ',
    title: `Quantum Exposure Assessment — ${c.name}`,
    numbering: { config: [{
      reference: 'cq',
      levels: [{ level: 0, format: LevelFormat.BULLET, text: '—', alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: convertInchesToTwip(0.3), hanging: convertInchesToTwip(0.2) } } } }],
    }]},
    styles: { default: { document: { run: { font: 'Calibri', size: 20, color: INK } } } },
    sections: [{
      properties: { page: { margin: { top: 1120, bottom: 1120, left: 1080, right: 1080 } } },
      headers: { default: new Header({ children: [new Paragraph({
        children: [
          t('CipherQ', { size: 14, bold: true, color: AMBER, caps: true, spacing: 60 }),
          t('     Quantum Exposure Assessment     ', { size: 14, color: MUTED, caps: true, spacing: 60 }),
          /* On every page, not just the first — pages get printed and
             circulated separately from the document they came out of. */
          t(c.classification, { size: 14, color: DRAFT ? RED : MUTED, bold: DRAFT }),
        ],
        spacing: { after: 220 },
      })]})},
      footers: { default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [
          t(`${c.name}   ·   `, { size: 14, color: MUTED }),
          new TextRun({ children: [PageNumber.CURRENT], font: 'Calibri', size: 14, color: AMBER, bold: true }),
        ],
      })]})},
      children: K,
    }],
  });

  return { buffer: await Packer.toBuffer(doc), sections: SECTIONS, numbered };
}

module.exports = { build, validate };
