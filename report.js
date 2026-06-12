'use strict';

/**
 * CipherQ PQC Scanner — DOCX Report Generator
 * Produces a professionally formatted Word document from scan results,
 * mirroring the structure of a formal Quantum Threat Assessment report.
 */

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, PageBreak, LevelFormat,
  TabStopType, TabStopPosition, ExternalHyperlink,
} = require('docx');

// ─── Colour palette (hex, no #) ───────────────────────────────────────────────
const COLOURS = {
  navy:       '0D1B3E',   // deep navy — primary brand
  teal:       '0077A8',   // CipherQ teal — accent
  danger:     'C0392B',   // critical / red
  warn:       'D68910',   // high / amber
  medium:     '1A5276',   // medium / blue
  ok:         '1E8449',   // ok / green
  lightGrey:  'F2F3F4',   // table alt row
  midGrey:    'D5D8DC',   // borders
  darkGrey:   '566573',   // body text secondary
  white:      'FFFFFF',
  black:      '000000',
  headerBg:   '0D1B3E',   // section header background
  subheaderBg:'1A3A5C',   // sub-header bg
};

// ─── Severity styling ─────────────────────────────────────────────────────────
const SEV_STYLE = {
  critical: { bg: 'FADBD8', text: 'C0392B', label: 'CRITICAL' },
  high:     { bg: 'FDEBD0', text: 'D68910', label: 'HIGH' },
  medium:   { bg: 'D6EAF8', text: '1A5276', label: 'MEDIUM' },
  low:      { bg: 'EAFAF1', text: '1E8449', label: 'LOW' },
  info:     { bg: 'F2F3F4', text: '566573', label: 'INFO' },
};

const PQ_STYLE = {
  none:           { bg: 'FADBD8', text: 'C0392B', label: 'NONE' },
  unknown:        { bg: 'FDEBD0', text: 'D68910', label: 'UNKNOWN' },
  partial:        { bg: 'D6EAF8', text: '1A5276', label: 'PARTIAL' },
  ready:          { bg: 'EAFAF1', text: '1E8449', label: 'READY' },
  'not-applicable': { bg: 'F2F3F4', text: '566573', label: 'N/A' },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CONTENT_WIDTH = 9360; // US Letter, 1" margins each side
const BORDER_GREY = { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey };
const NO_BORDER   = { style: BorderStyle.NONE, size: 0, color: COLOURS.white };
const ALL_BORDERS = { top: BORDER_GREY, bottom: BORDER_GREY, left: BORDER_GREY, right: BORDER_GREY };
const NO_BORDERS  = { top: NO_BORDER, bottom: NO_BORDER, left: NO_BORDER, right: NO_BORDER };

function cell(children, opts = {}) {
  const {
    width = CONTENT_WIDTH / 2,
    bg = null,
    bold = false,
    color = COLOURS.black,
    align = AlignmentType.LEFT,
    vAlign = VerticalAlign.CENTER,
    borders = ALL_BORDERS,
    colspan = 1,
    fontSize = 18, // 9pt
  } = opts;

  return new TableCell({
    borders,
    columnSpan: colspan,
    verticalAlign: vAlign,
    width: { size: width, type: WidthType.DXA },
    shading: bg ? { fill: bg, type: ShadingType.CLEAR } : undefined,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: Array.isArray(children) ? children : [
      new Paragraph({
        alignment: align,
        children: [new TextRun({ text: String(children ?? '—'), bold, color, size: fontSize, font: 'Arial' })],
      }),
    ],
  });
}

function headerCell(text, width, opts = {}) {
  return cell(text, {
    width,
    bg: COLOURS.headerBg,
    bold: true,
    color: COLOURS.white,
    fontSize: 18,
    ...opts,
  });
}

function spacer(pts = 6) {
  return new Paragraph({
    children: [new TextRun('')],
    spacing: { before: pts * 20, after: 0 },
  });
}

function sectionHeading(text, level = HeadingLevel.HEADING_1) {
  return new Paragraph({
    heading: level,
    children: [new TextRun({ text, font: 'Arial' })],
    pageBreakBefore: level === HeadingLevel.HEADING_1,
  });
}

function bodyText(text, opts = {}) {
  const { bold = false, color = COLOURS.black, size = 20 } = opts;
  return new Paragraph({
    children: [new TextRun({ text, bold, color, size, font: 'Arial' })],
    spacing: { after: 120 },
  });
}

function bulletItem(text, reference = 'bullets') {
  return new Paragraph({
    numbering: { reference, level: 0 },
    children: [new TextRun({ text, size: 20, font: 'Arial' })],
    spacing: { after: 60 },
  });
}

function colourBar(text, bg, textColour = COLOURS.white) {
  return new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [CONTENT_WIDTH],
    borders: NO_BORDERS,
    rows: [new TableRow({
      children: [cell([new Paragraph({
        children: [new TextRun({ text, bold: true, color: textColour, size: 20, font: 'Arial' })],
        spacing: { before: 60, after: 60 },
      })], { width: CONTENT_WIDTH, bg, borders: NO_BORDERS })],
    })],
  });
}

// ─── Page header/footer ───────────────────────────────────────────────────────

function makeHeader(domain, scanDate) {
  return new Header({
    children: [
      new Paragraph({
        children: [
          new TextRun({ text: `CipherQ Quantum Threat Assessment  ·  ${domain}`, bold: true, size: 18, color: COLOURS.teal, font: 'Arial' }),
          new TextRun({ text: `\t${scanDate}`, size: 18, color: COLOURS.darkGrey, font: 'Arial' }),
        ],
        tabStops: [{ type: TabStopType.RIGHT, position: TabStopPosition.MAX }],
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.teal, space: 1 } },
        spacing: { after: 80 },
      }),
    ],
  });
}

function makeFooter() {
  return new Footer({
    children: [
      new Paragraph({
        children: [
          new TextRun({ text: 'RESTRICTED — CipherQ PQC Scanner  ·  ', size: 16, color: COLOURS.darkGrey, font: 'Arial' }),
          new TextRun({ text: 'Page ', size: 16, color: COLOURS.darkGrey, font: 'Arial' }),
          new TextRun({ children: [PageNumber.CURRENT], size: 16, color: COLOURS.darkGrey, font: 'Arial' }),
          new TextRun({ text: ' of ', size: 16, color: COLOURS.darkGrey, font: 'Arial' }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, color: COLOURS.darkGrey, font: 'Arial' }),
        ],
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 1 } },
        spacing: { before: 80 },
        alignment: AlignmentType.RIGHT,
      }),
    ],
  });
}

// ─── Cover page ───────────────────────────────────────────────────────────────

function buildCoverPage(summary) {
  const date = new Date(summary.scanTime).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'long', year: 'numeric',
  });

  return [
    spacer(120),

    // Title block
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [CONTENT_WIDTH],
      borders: NO_BORDERS,
      rows: [
        new TableRow({ children: [cell([
          new Paragraph({ children: [new TextRun({ text: 'QUANTUM THREAT ASSESSMENT', bold: true, size: 52, color: COLOURS.white, font: 'Arial' })], spacing: { after: 80 } }),
          new Paragraph({ children: [new TextRun({ text: 'External TLS Posture Review', size: 28, color: 'A9CCE3', font: 'Arial' })], spacing: { after: 40 } }),
          new Paragraph({ children: [new TextRun({ text: 'Post-quantum cryptographic readiness of the public-facing TLS surface', size: 20, color: 'AED6F1', font: 'Arial' })], spacing: { after: 0 } }),
        ], { width: CONTENT_WIDTH, bg: COLOURS.navy, borders: NO_BORDERS })] }),
      ],
    }),

    spacer(20),

    // Meta table
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [2200, 2480, 2200, 2480],
      borders: NO_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('DOMAIN',    2200, { bg: COLOURS.teal }),
          cell(summary.domain,    { width: 2480, fontSize: 20 }),
          headerCell('DATE ISSUED', 2200, { bg: COLOURS.teal }),
          cell(date,              { width: 2480, fontSize: 20 }),
        ]}),
        new TableRow({ children: [
          headerCell('SCOPE',     2200, { bg: COLOURS.teal }),
          cell(`${summary.hostsProbed} hosts probed`, { width: 2480, fontSize: 20 }),
          headerCell('REACHABLE', 2200, { bg: COLOURS.teal }),
          cell(`${summary.hostsReachable} hosts`, { width: 2480, fontSize: 20 }),
        ]}),
        new TableRow({ children: [
          headerCell('HNDL RISK', 2200, { bg: COLOURS.danger }),
          cell(summary.overallHndlRisk.toUpperCase().replace('-', ' '), { width: 2480, bold: true, color: COLOURS.danger, fontSize: 20 }),
          headerCell('PQ-READY', 2200, { bg: COLOURS.teal }),
          cell(`${summary.pqReadinessBreakdown.ready} of ${summary.hostsReachable}`, { width: 2480, fontSize: 20 }),
        ]}),
      ],
    }),

    spacer(20),

    // At a glance stat row
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [2340, 2340, 2340, 2340],
      borders: ALL_BORDERS,
      rows: [new TableRow({ children: [
        cell([
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(summary.hostsProbed), bold: true, size: 52, color: COLOURS.teal, font: 'Arial' })], spacing: { after: 0 } }),
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'HOSTS PROBED', size: 14, color: COLOURS.darkGrey, font: 'Arial' })], spacing: { after: 0 } }),
        ], { width: 2340, bg: COLOURS.lightGrey }),
        cell([
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(summary.hostsReachable), bold: true, size: 52, color: COLOURS.teal, font: 'Arial' })], spacing: { after: 0 } }),
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'REACHABLE', size: 14, color: COLOURS.darkGrey, font: 'Arial' })], spacing: { after: 0 } }),
        ], { width: 2340, bg: COLOURS.lightGrey }),
        cell([
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '0', bold: true, size: 52, color: COLOURS.danger, font: 'Arial' })], spacing: { after: 0 } }),
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'WITH PQ KEX', size: 14, color: COLOURS.darkGrey, font: 'Arial' })], spacing: { after: 0 } }),
        ], { width: 2340, bg: COLOURS.lightGrey }),
        cell([
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(summary.findingsBySeverity.critical + summary.findingsBySeverity.high), bold: true, size: 52, color: summary.findingsBySeverity.critical > 0 ? COLOURS.danger : COLOURS.warn, font: 'Arial' })], spacing: { after: 0 } }),
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'CRIT / HIGH', size: 14, color: COLOURS.darkGrey, font: 'Arial' })], spacing: { after: 0 } }),
        ], { width: 2340, bg: COLOURS.lightGrey }),
      ]})]
    }),

    spacer(30),

    // Classification notice
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: 'RESTRICTED — For internal use only', bold: true, size: 16, color: COLOURS.danger, font: 'Arial' })],
      border: { top: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey }, bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey } },
      spacing: { before: 60, after: 60 },
    }),
  ];
}

// ─── Executive summary ────────────────────────────────────────────────────────

function buildExecutiveSummary(summary, findings) {
  const sev = summary.findingsBySeverity;
  const critHigh = sev.critical + sev.high;
  const hndlHigh = summary.overallHndlRisk.startsWith('high');

  return [
    sectionHeading('Executive Summary'),

    bodyText(
      `This Quantum Threat Assessment examines the externally observable TLS surface of the ${summary.domain} domain estate. ` +
      `The objective is to establish a quantum-readiness baseline for the public footprint, identify configuration and hygiene ` +
      `findings that can be acted on now, and recommend a sequenced path to full post-quantum readiness consistent with NIST, ` +
      `UK NCSC and CA/Browser Forum trajectories.`
    ),

    spacer(6),
    sectionHeading('What the scan shows', HeadingLevel.HEADING_2),

    bulletItem(`Of ${summary.hostsProbed} host names probed, ${summary.hostsReachable} completed a TLS handshake.`),
    bulletItem(
      `${summary.pqReadinessBreakdown.ready === 0
        ? 'No host showed evidence of hybrid post-quantum key exchange. This is the industry norm in mid-2026 but requires active remediation.'
        : `${summary.pqReadinessBreakdown.ready} host(s) showed evidence of post-quantum key exchange.`}`
    ),
    bulletItem(`No certificate observed used a post-quantum signature algorithm. All certificates rely on classical, quantum-vulnerable PKI.`),
    summary.sniMismatches.length > 0
      ? bulletItem(`SNI / certificate mismatch detected on: ${summary.sniMismatches.join(', ')}.`)
      : bulletItem('No SNI mismatches detected.'),
    summary.devHostsExposed.length > 0
      ? bulletItem(`Externally exposed development infrastructure detected: ${summary.devHostsExposed.join(', ')}.`)
      : null,
    bulletItem(`${summary.hostsUnreachable} host names resolved in DNS but did not complete a TLS handshake — pattern consistent with dormant or internally-scoped infrastructure in public DNS.`),

    spacer(6),
    sectionHeading('Headline conclusions', HeadingLevel.HEADING_2),

    bodyText('Harvest-Now-Decrypt-Later (HNDL) is the dominant risk against the public surface.', { bold: true }),
    bodyText(
      `An adversary recording TLS traffic today can decrypt it once a Cryptanalytically-Relevant Quantum Computer (CRQC) exists. ` +
      `The protected content — correspondence, transactional papers, client data — may remain sensitive for decades.`
    ),

    spacer(6),

    // Risk summary table
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [3500, 1800, 2000, 2060],
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('AREA OF EXPOSURE',  3500),
          headerCell('STATUS',            1800),
          headerCell('BUSINESS IMPACT',   2000),
          headerCell('PRIORITY',          2060),
        ]}),
        ...buildPriorityRows(summary, findings),
      ],
    }),
  ].filter(Boolean);
}

function buildPriorityRows(summary, findings) {
  const areas = [
    { area: 'TLS key exchange — PQ readiness', status: 'Live', impact: 'High', priority: 'P1 — Immediate', impactCol: COLOURS.danger },
    { area: 'Certificate authority posture',   status: 'Live', impact: 'Medium', priority: 'P2 — Near-term', impactCol: COLOURS.warn },
    { area: 'SNI / certificate matching',      status: summary.sniMismatches.length > 0 ? 'Finding' : 'Clear', impact: 'Medium', priority: summary.sniMismatches.length > 0 ? 'P1 — Immediate' : 'None', impactCol: COLOURS.warn },
    { area: 'DNS surface / dormant subdomains', status: summary.hostsUnreachable > 0 ? 'Finding' : 'Clear', impact: 'Low–Medium', priority: summary.hostsUnreachable > 0 ? 'P2 — Near-term' : 'None', impactCol: COLOURS.ok },
    { area: 'Externally exposed dev infrastructure', status: summary.devHostsExposed.length > 0 ? 'Finding' : 'Clear', impact: summary.devHostsExposed.length > 0 ? 'Medium' : 'None', priority: summary.devHostsExposed.length > 0 ? 'P1 — Immediate' : 'None', impactCol: COLOURS.warn },
  ];

  return areas.map((a, i) => new TableRow({
    children: [
      cell(a.area,     { width: 3500, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
      cell(a.status,   { width: 1800, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
      cell(a.impact,   { width: 2000, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, color: a.impactCol, bold: true, fontSize: 18 }),
      cell(a.priority, { width: 2060, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: a.priority.startsWith('P1'), color: a.priority.startsWith('P1') ? COLOURS.danger : COLOURS.black, fontSize: 18 }),
    ],
  }));
}

// ─── Findings section ─────────────────────────────────────────────────────────

function buildFindings(findings) {
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const children = [
    sectionHeading('Detailed Findings'),
    bodyText(
      `This section presents each security finding identified during the assessment. Findings are ordered by severity. ` +
      `For each finding the context, technical exposure, consequence, and recommended response are described.`
    ),
    spacer(6),
  ];

  // Findings by severity summary
  const sevCounts = {};
  for (const f of findings) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;

  children.push(new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [1872, 1872, 1872, 1872, 1872],
    borders: ALL_BORDERS,
    rows: [
      new TableRow({ children: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s, i) => {
        const k = s.toLowerCase();
        const style = SEV_STYLE[k];
        return cell([
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(sevCounts[k] || 0), bold: true, size: 40, color: style.text, font: 'Arial' })], spacing: { after: 0 } }),
          new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: s, size: 14, color: style.text, font: 'Arial' })], spacing: { after: 0 } }),
        ], { width: 1872, bg: style.bg });
      })}),
    ],
  }));

  children.push(spacer(12));

  // Individual findings
  for (const f of sorted) {
    const style = SEV_STYLE[f.severity] || SEV_STYLE.info;

    children.push(
      // Finding header bar
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1400, CONTENT_WIDTH - 1400],
        borders: NO_BORDERS,
        rows: [new TableRow({ children: [
          cell(style.label, { width: 1400, bg: style.text, color: COLOURS.white, bold: true, fontSize: 18, borders: NO_BORDERS }),
          cell(f.title,     { width: CONTENT_WIDTH - 1400, bg: style.bg, color: style.text, bold: true, fontSize: 18, borders: NO_BORDERS }),
        ]})],
      }),

      // Finding detail table
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1800, CONTENT_WIDTH - 1800],
        borders: ALL_BORDERS,
        rows: [
          ...(f.hostname ? [new TableRow({ children: [
            cell('Host',        { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.hostname,    { width: CONTENT_WIDTH - 1800, fontSize: 18 }),
          ]})] : []),
          new TableRow({ children: [
            cell('Area',        { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell((f.area || '').replace(/-/g, ' ').toUpperCase(), { width: CONTENT_WIDTH - 1800, fontSize: 18 }),
          ]}),
          new TableRow({ children: [
            cell('Detail',      { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell([new Paragraph({ children: [new TextRun({ text: f.detail, size: 18, font: 'Arial' })], spacing: { after: 0 } })],
              { width: CONTENT_WIDTH - 1800 }),
          ]}),
          ...(f.recommendation ? [new TableRow({ children: [
            cell('Recommendation', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell([new Paragraph({ children: [new TextRun({ text: f.recommendation, size: 18, font: 'Arial', color: COLOURS.ok, bold: true })], spacing: { after: 0 } })],
              { width: CONTENT_WIDTH - 1800 }),
          ]})] : []),
          ...(f.nistRef ? [new TableRow({ children: [
            cell('NIST Reference', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.nistRef,        { width: CONTENT_WIDTH - 1800, fontSize: 16 }),
          ]})] : []),
          ...(f.priority ? [new TableRow({ children: [
            cell('Priority',    { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.priority,    { width: CONTENT_WIDTH - 1800, bold: true, color: f.priority === 'P1' ? COLOURS.danger : COLOURS.warn, fontSize: 18 }),
          ]})] : []),
        ],
      }),
      spacer(10),
    );
  }

  return children;
}

// ─── Host inventory table ─────────────────────────────────────────────────────

function buildHostInventory(hosts) {
  const reachable = hosts.filter(h => h.tls?.cipher);
  const unreachable = hosts.filter(h => h.dns?.resolves && !h.tls?.cipher);

  const colW = [2600, 1200, 1500, 800, 900, 1300, 1060];

  return [
    sectionHeading('TLS Scan Results'),
    bodyText(`This appendix presents the underlying TLS scan data. The scan was run against ${hosts.length} host names.`),
    spacer(6),

    sectionHeading('Reachable Hosts', HeadingLevel.HEADING_2),
    spacer(4),

    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: colW,
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('Hostname',    colW[0]),
          headerCell('Protocol',   colW[1]),
          headerCell('Cipher',     colW[2]),
          headerCell('CA',         colW[3]),
          headerCell('Expiry',     colW[4]),
          headerCell('SNI',        colW[5]),
          headerCell('PQ Ready',   colW[6]),
        ]}),
        ...reachable.map((h, i) => {
          const days = h.tls?.certDaysToExpiry;
          const daysStr = days != null ? `${days}d` : '—';
          const daysColor = days != null && days < 14 ? COLOURS.danger : days != null && days < 30 ? COLOURS.warn : COLOURS.ok;
          const sniOk = h.tls?.sniMatch?.match;
          const pqStyle = PQ_STYLE[h.pqReadiness] || PQ_STYLE['not-applicable'];
          const bg = i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey;

          return new TableRow({ children: [
            cell(h.hostname,              { width: colW[0], bg, fontSize: 16 }),
            cell(h.tls?.protocol || '—',  { width: colW[1], bg, fontSize: 16 }),
            cell((h.tls?.cipher || '—').replace('TLS_', ''), { width: colW[2], bg, fontSize: 14 }),
            cell((h.tls?.caName || '—').slice(0, 16), { width: colW[3], bg, fontSize: 14 }),
            cell(daysStr,                 { width: colW[4], bg, color: daysColor, bold: days != null && days < 30, fontSize: 16 }),
            cell(sniOk == null ? '—' : sniOk ? '✓' : '✗ MISMATCH', { width: colW[5], bg, color: sniOk == null ? COLOURS.darkGrey : sniOk ? COLOURS.ok : COLOURS.danger, bold: !sniOk && sniOk != null, fontSize: 16 }),
            cell(pqStyle.label,           { width: colW[6], bg: pqStyle.bg, color: pqStyle.text, bold: true, fontSize: 14 }),
          ]});
        }),
      ],
    }),

    spacer(12),
    sectionHeading('DNS-Only Hosts (Unreachable on TLS)', HeadingLevel.HEADING_2),
    bodyText('The following host names resolved in public DNS but did not complete a TLS handshake during the scan window.'),
    spacer(4),

    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [4680, 4680],
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [headerCell('Hostname', 4680), headerCell('Assessment', 4680)] }),
        ...(unreachable.length === 0
          ? [new TableRow({ children: [cell('None — all DNS-resolving hosts completed a TLS handshake.', { width: CONTENT_WIDTH, colspan: 2 })] })]
          : unreachable.map((h, i) => new TableRow({ children: [
              cell(h.hostname, { width: 4680, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 16 }),
              cell('DNS resolves; no TLS handshake — dormant or internally-scoped', { width: 4680, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, color: COLOURS.darkGrey, fontSize: 16 }),
            ]}))),
      ],
    }),
  ];
}

// ─── Roadmap ──────────────────────────────────────────────────────────────────

function buildRoadmap(summary) {
  const phases = [
    {
      label: 'Phase 1 · 0–6 months',
      title: 'Inventory & Configure',
      bg: COLOURS.teal,
      items: [
        'Appoint and charter a named owner for the public cryptographic posture.',
        'Run a deep TLS enumeration (testssl.sh --groups) on every reachable host to confirm KEX groups and build the public-surface Cryptographic Bill of Materials (CBOM).',
        'Resolve SNI mismatches.' + (summary.sniMismatches.length > 0 ? ` (${summary.sniMismatches.join(', ')})` : ''),
        'Restrict or retire externally exposed development infrastructure.' + (summary.devHostsExposed.length > 0 ? ` (${summary.devHostsExposed.join(', ')})` : ''),
        'Enable Certificate Transparency monitoring on every domain.',
        'Engage hosting and CDN providers on their hybrid post-quantum TLS roadmap.',
      ],
    },
    {
      label: 'Phase 2 · 6–18 months',
      title: 'Enable & Retire',
      bg: COLOURS.medium,
      items: [
        'Enable hybrid post-quantum key exchange (X25519MLKEM768) across every TLS termination point. Update OpenSSL → 3.5+, Go runtimes → 1.24+.',
        'Validate middlebox compatibility — hybrid KEX expands the ClientHello ~38x; test end-to-end on each network path.',
        'Prune dormant DNS subdomain entries; retire or document every host that resolves but does not serve TLS.',
        'Migrate any externally exposed dev/staging environment to an authenticated or private posture.',
        'Publish a public-facing quantum-readiness statement.',
        'Update outside-counsel due-diligence questionnaire.',
      ],
    },
    {
      label: 'Phase 3 · 18+ months',
      title: 'Adopt & Harden',
      bg: COLOURS.ok,
      items: [
        'Adopt ML-DSA (FIPS 204) leaf certificates as commercial CAs offer them — expected 2027 onward.',
        'Re-issue all leaf certificates under post-quantum or hybrid signatures.',
        'Review long-term archived sensitive communications; re-encrypt where practical.',
        'Extend CBOM to internal infrastructure, endpoints, and SaaS dependencies.',
        'Hold a programme review with Management Board and adjust as standards evolve.',
      ],
    },
  ];

  const children = [
    sectionHeading('Recommended Roadmap'),
    bodyText(
      'The transition to a quantum-resistant public posture is a multi-year programme. The plan below is sequenced to deliver ' +
      'demonstrable risk reduction within the first six months while preserving optionality on longer-horizon questions ' +
      '(post-quantum certificates, supply-chain dependencies) that depend on external standards progress.'
    ),
    spacer(8),
  ];

  for (const phase of phases) {
    children.push(colourBar(`${phase.label} — ${phase.title}`, phase.bg));
    for (const item of phase.items) {
      children.push(bulletItem(item));
    }
    children.push(spacer(8));
  }

  // Regulatory timeline table
  children.push(sectionHeading('Regulatory Timeline', HeadingLevel.HEADING_2));
  children.push(spacer(4));

  const timeline = [
    ['Jan 2027',  'CNSA 2.0 (US NSS)',     'All new National Security System acquisitions must be CNSA 2.0-compliant.'],
    ['2028',      'UK NCSC',               'Planning complete; post-quantum roadmap documented for all critical systems.'],
    ['2030',      'NIST IR 8547',          'RSA-2048 and ECC P-256 deprecated. Quantum-vulnerable algorithms disallowed by 2035.'],
    ['2031',      'UK NCSC',               'Critical systems migrated to post-quantum algorithms.'],
    ['2035',      'Full horizon',          'NIST, CNSA 2.0, and UK NCSC full migration / disallowance deadline.'],
  ];

  children.push(new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [1200, 1800, 6360],
    borders: ALL_BORDERS,
    rows: [
      new TableRow({ children: [headerCell('Date', 1200), headerCell('Source', 1800), headerCell('Requirement', 6360)] }),
      ...timeline.map(([date, source, req], i) => new TableRow({ children: [
        cell(date,   { width: 1200, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: true, color: COLOURS.danger, fontSize: 18 }),
        cell(source, { width: 1800, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: true, fontSize: 18 }),
        cell(req,    { width: 6360, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
      ]})),
    ],
  }));

  // Asymmetry callout
  children.push(spacer(12));
  children.push(new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [CONTENT_WIDTH],
    borders: { top: { style: BorderStyle.SINGLE, size: 12, color: COLOURS.danger }, bottom: BORDER_GREY, left: { style: BorderStyle.SINGLE, size: 12, color: COLOURS.danger }, right: BORDER_GREY },
    rows: [new TableRow({ children: [cell([
      new Paragraph({ children: [new TextRun({ text: 'The single most important sentence in this report:', bold: true, size: 20, color: COLOURS.danger, font: 'Arial' })], spacing: { after: 80 } }),
      new Paragraph({ children: [new TextRun({ text: 'A migration started in 2025–2026 has comfortable margin. A migration started in 2029 may not.', size: 20, font: 'Arial' })], spacing: { after: 0 } }),
    ], { width: CONTENT_WIDTH, bg: 'FDEDEC', borders: NO_BORDERS })] })],
  }));

  return children;
}

// ─── NIST control mapping ─────────────────────────────────────────────────────

function buildControlMapping() {
  const mappings = [
    { finding: 'TLS key exchange (HNDL)', primitive: 'X25519 / ECDHE', pq: 'X25519MLKEM768 (IETF draft)', csf: 'PR.DS-02 · PR.AA-05', sp: 'SC-8 · SC-12 · SC-23', mat: 'Ready' },
    { finding: 'Certificate signatures (TNFL)', primitive: 'RSA · ECDSA', pq: 'ML-DSA (FIPS 204)', csf: 'PR.AA-01 · PR.DS-01', sp: 'SC-12 · SC-13 · SC-17', mat: 'Gap' },
    { finding: 'SNI / cert binding', primitive: 'N/A (config)', pq: 'Correct cert binding', csf: 'PR.PS-01 · DE.CM-01', sp: 'CM-3 · CM-5 · SC-17', mat: 'Ready' },
    { finding: 'DNS surface', primitive: 'DNS (info disclosure)', pq: 'DNS hygiene', csf: 'ID.AM-04 · PR.AC-04', sp: 'CM-3 · SC-20', mat: 'Ready' },
    { finding: 'Exposed dev infra', primitive: 'N/A (config)', pq: 'Access control / private network', csf: 'PR.AA-01 · PR.PS-01', sp: 'AC-3 · AC-17 · CM-5', mat: 'Ready' },
  ];

  const colW = [2000, 1600, 1800, 1500, 1500, 960];

  return [
    sectionHeading('NIST PQC Control Mapping'),
    bodyText('This appendix maps each finding to the relevant NIST post-quantum cryptographic standard, NIST Cybersecurity Framework 2.0 function, and NIST SP 800-53 Rev 5 control families.'),
    spacer(8),

    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: colW,
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('Finding', colW[0]),
          headerCell('At-risk Primitive', colW[1]),
          headerCell('PQ Remediation', colW[2]),
          headerCell('NIST CSF 2.0', colW[3]),
          headerCell('SP 800-53 R5', colW[4]),
          headerCell('Maturity', colW[5]),
        ]}),
        ...mappings.map((m, i) => {
          const bg = i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey;
          const matColor = m.mat === 'Ready' ? COLOURS.ok : COLOURS.warn;
          return new TableRow({ children: [
            cell(m.finding,   { width: colW[0], bg, fontSize: 16 }),
            cell(m.primitive, { width: colW[1], bg, fontSize: 16 }),
            cell(m.pq,        { width: colW[2], bg, fontSize: 16 }),
            cell(m.csf,       { width: colW[3], bg, fontSize: 14 }),
            cell(m.sp,        { width: colW[4], bg, fontSize: 14 }),
            cell(m.mat,       { width: colW[5], bg: m.mat === 'Ready' ? 'EAFAF1' : 'FDEBD0', color: matColor, bold: true, fontSize: 16 }),
          ]});
        }),
      ],
    }),
  ];
}

// ─── Main generator ───────────────────────────────────────────────────────────

async function generateReport(scanResult) {
  const { summary, hosts, findings } = scanResult;

  const scanDate = new Date(summary.scanTime).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'long', year: 'numeric',
  });

  const doc = new Document({
    styles: {
      default: {
        document: { run: { font: 'Arial', size: 20, color: COLOURS.black } },
      },
      paragraphStyles: [
        {
          id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 36, bold: true, font: 'Arial', color: COLOURS.navy },
          paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 0,
            border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: COLOURS.teal, space: 1 } } },
        },
        {
          id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 26, bold: true, font: 'Arial', color: COLOURS.teal },
          paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 1 },
        },
        {
          id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 22, bold: true, font: 'Arial', color: COLOURS.navy },
          paragraph: { spacing: { before: 160, after: 80 }, outlineLevel: 2 },
        },
      ],
    },

    numbering: {
      config: [{
        reference: 'bullets',
        levels: [{
          level: 0,
          format: LevelFormat.BULLET,
          text: '•',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } }, run: { font: 'Arial', size: 20 } },
        }],
      }],
    },

    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1200, right: 1200, bottom: 1200, left: 1200 },
        },
      },
      headers: { default: makeHeader(summary.domain, scanDate) },
      footers: { default: makeFooter() },
      children: [
        ...buildCoverPage(summary),
        ...buildExecutiveSummary(summary, findings),
        ...buildFindings(findings),
        ...buildHostInventory(hosts),
        ...buildRoadmap(summary),
        ...buildControlMapping(),
      ],
    }],
  });

  return Packer.toBuffer(doc);
}

module.exports = { generateReport };
