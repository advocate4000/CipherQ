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

function buildExecutiveSummary(summary, findings, dnsData, httpData, networkData) {
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
        ...buildPriorityRows(summary, findings, dnsData, httpData, networkData),
      ],
    }),
  ].filter(Boolean);
}

// ─── DNS Security Section ─────────────────────────────────────────────────────

function buildDNSSection(dnsData) {
  if (!dnsData || !dnsData.report) return [];

  const { report, findings } = dnsData;
  const s = report.summary;
  const checks = report.checks || {};
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted = [...findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const children = [
    sectionHeading('DNS Security Assessment'),
    bodyText(
      `This section presents the results of the DNS vulnerability assessment conducted alongside the TLS surface review. ` +
      `DNS security controls — zone transfer restrictions, DNSSEC, email authentication, CAA records, and subdomain ` +
      `hygiene — form the foundational layer of trust on which all certificate-based security depends. Weaknesses here ` +
      `can undermine TLS posture regardless of cryptographic strength.`
    ),
    spacer(8),

    // ── Status overview table ─────────────────────────────────────────────────
    sectionHeading('DNS Security Posture Overview', HeadingLevel.HEADING_2),
    spacer(4),

    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [3120, 2080, 2080, 2080],
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('CHECK',           3120),
          headerCell('STATUS',          2080),
          headerCell('RISK LEVEL',      2080),
          headerCell('ACTION REQUIRED', 2080),
        ]}),
        ...[
          {
            check: 'Zone Transfer (AXFR)',
            status: s.axfrVulnerable ? 'VULNERABLE' : 'SECURE',
            risk: s.axfrVulnerable ? 'CRITICAL' : 'None',
            action: s.axfrVulnerable ? 'Restrict AXFR to authorised secondaries immediately' : 'No action required',
            riskCol: s.axfrVulnerable ? COLOURS.danger : COLOURS.ok,
          },
          {
            check: 'DNSSEC',
            status: s.dnssecDeployed ? 'DEPLOYED' : 'NOT DEPLOYED',
            risk: s.dnssecDeployed ? 'None' : 'MEDIUM',
            action: s.dnssecDeployed ? 'No action required' : 'Enable DNSSEC signing at registrar',
            riskCol: s.dnssecDeployed ? COLOURS.ok : COLOURS.warn,
          },
          {
            check: 'DMARC Policy',
            status: (s.dmarcPolicy || 'MISSING').toUpperCase(),
            risk: s.dmarcPolicy === 'reject' ? 'None' : s.dmarcPolicy === 'quarantine' ? 'LOW' : s.dmarcPolicy === 'none' ? 'MEDIUM' : 'HIGH',
            action: s.dmarcPolicy === 'reject' ? 'Monitor reports' : s.dmarcPolicy ? `Advance policy from ${s.dmarcPolicy} to reject` : 'Publish DMARC record immediately',
            riskCol: s.dmarcPolicy === 'reject' ? COLOURS.ok : s.dmarcPolicy === 'quarantine' ? COLOURS.medium : COLOURS.danger,
          },
          {
            check: 'SPF Record',
            status: s.spfPresent ? 'PRESENT' : 'MISSING',
            risk: s.spfPresent ? 'None' : 'HIGH',
            action: s.spfPresent ? 'Verify -all qualifier' : 'Publish SPF record with -all hardfail',
            riskCol: s.spfPresent ? COLOURS.ok : COLOURS.danger,
          },
          {
            check: 'DKIM Signing',
            status: (checks.emailSecurity?.dkimSelectors?.length > 0) ? `FOUND (${checks.emailSecurity.dkimSelectors.join(', ')})` : 'NOT DETECTED',
            risk: (checks.emailSecurity?.dkimSelectors?.length > 0) ? 'None' : 'MEDIUM',
            action: (checks.emailSecurity?.dkimSelectors?.length > 0) ? 'No action required' : 'Verify DKIM is configured on all mail senders',
            riskCol: (checks.emailSecurity?.dkimSelectors?.length > 0) ? COLOURS.ok : COLOURS.warn,
          },
          {
            check: 'CAA Records',
            status: s.caaPresent ? 'PRESENT' : 'MISSING',
            risk: s.caaPresent ? 'None' : 'MEDIUM',
            action: s.caaPresent ? 'Add iodef tag for misissuance reports' : 'Publish CAA records restricting certificate issuance',
            riskCol: s.caaPresent ? COLOURS.ok : COLOURS.warn,
          },
          {
            check: 'Subdomain Takeover',
            status: s.takeoverCount > 0 ? `${s.takeoverCount} VULNERABLE` : s.danglingCNAMECount > 0 ? `${s.danglingCNAMECount} DANGLING` : 'CLEAR',
            risk: s.takeoverCount > 0 ? 'CRITICAL' : s.danglingCNAMECount > 0 ? 'HIGH' : 'None',
            action: s.takeoverCount > 0 ? 'Reclaim or remove dangling DNS records immediately' : s.danglingCNAMECount > 0 ? 'Verify dangling CNAMEs are not claimable' : 'No action required',
            riskCol: s.takeoverCount > 0 ? COLOURS.danger : s.danglingCNAMECount > 0 ? COLOURS.warn : COLOURS.ok,
          },
          {
            check: 'Open Resolver',
            status: s.openResolverCount > 0 ? `${s.openResolverCount} OPEN` : 'SECURE',
            risk: s.openResolverCount > 0 ? 'HIGH' : 'None',
            action: s.openResolverCount > 0 ? 'Disable recursive resolution on authoritative nameservers' : 'No action required',
            riskCol: s.openResolverCount > 0 ? COLOURS.danger : COLOURS.ok,
          },
        ].map((row, i) => new TableRow({ children: [
          cell(row.check,  { width: 3120, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: true, fontSize: 18 }),
          cell(row.status, { width: 2080, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
          cell(row.risk,   { width: 2080, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, color: row.riskCol, bold: row.risk !== 'None', fontSize: 18 }),
          cell(row.action, { width: 2080, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 16 }),
        ]})),
      ],
    }),

    spacer(12),

    // ── Email security detail ─────────────────────────────────────────────────
    sectionHeading('Email Security Detail', HeadingLevel.HEADING_2),
    spacer(4),
  ];

  // SPF detail
  const spf = checks.emailSecurity?.spf;
  const dmarc = checks.emailSecurity?.dmarc;

  children.push(new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [2200, CONTENT_WIDTH - 2200],
    borders: ALL_BORDERS,
    rows: [
      new TableRow({ children: [
        cell('SPF Record', { width: 2200, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
        cell(spf ? spf.raw : 'Not found', { width: CONTENT_WIDTH - 2200, fontSize: 16 }),
      ]}),
      new TableRow({ children: [
        cell('SPF Qualifier', { width: 2200, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
        cell(spf ? ({ '-': '-all (hardfail — correct)', '~': '~all (softfail)', '?': '?all (neutral — no protection)', '+': '+all (CRITICAL — allows all senders)' }[spf.qualifier] || spf.qualifier || 'Unknown') : 'N/A — SPF not found', {
          width: CONTENT_WIDTH - 2200, fontSize: 18,
          color: spf?.qualifier === '-' ? COLOURS.ok : spf?.qualifier === '~' ? COLOURS.warn : spf?.qualifier ? COLOURS.danger : COLOURS.danger,
          bold: !!spf?.qualifier && spf.qualifier !== '-',
        }),
      ]}),
      new TableRow({ children: [
        cell('DMARC Record', { width: 2200, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
        cell(dmarc ? dmarc.raw : 'Not found', { width: CONTENT_WIDTH - 2200, fontSize: 16 }),
      ]}),
      new TableRow({ children: [
        cell('DMARC Policy', { width: 2200, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
        cell(dmarc ? `p=${dmarc.policy}${dmarc.pct < 100 ? ` (${dmarc.pct}% enforcement)` : ''} · sp=${dmarc.subdomainPolicy || 'inherited'} · rua=${dmarc.rua || 'not set'}` : 'N/A — DMARC not found', {
          width: CONTENT_WIDTH - 2200, fontSize: 18,
          color: dmarc?.policy === 'reject' ? COLOURS.ok : dmarc?.policy ? COLOURS.warn : COLOURS.danger,
        }),
      ]}),
      new TableRow({ children: [
        cell('DKIM Selectors Found', { width: 2200, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
        cell((checks.emailSecurity?.dkimSelectors?.length > 0 ? checks.emailSecurity.dkimSelectors.join(', ') : 'None detected at common selectors'), {
          width: CONTENT_WIDTH - 2200, fontSize: 18,
        }),
      ]}),
    ],
  }));

  children.push(spacer(12));

  // ── Zone transfer detail ──────────────────────────────────────────────────
  const zoneXfer = checks.zoneTransfer;
  if (zoneXfer?.nameservers?.length > 0) {
    children.push(sectionHeading('Nameserver / Zone Transfer Detail', HeadingLevel.HEADING_2));
    children.push(spacer(4));
    children.push(new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [3500, 2430, 3430],
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('Nameserver', 3500),
          headerCell('IP Address', 2430),
          headerCell('AXFR Result', 3430),
        ]}),
        ...(zoneXfer.axfrDetails || []).map((r, i) => new TableRow({ children: [
          cell(r.nsHostname || r.nameserver, { width: 3500, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
          cell(r.nameserver || r.ip || '—', { width: 2430, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
          cell(r.vulnerable ? 'VULNERABLE — Zone transfer permitted' : (r.reason || 'Refused'), {
            width: 3430,
            bg: r.vulnerable ? 'FADBD8' : i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey,
            color: r.vulnerable ? COLOURS.danger : COLOURS.ok,
            bold: r.vulnerable,
            fontSize: 18,
          }),
        ]})),
      ],
    }));
    children.push(spacer(12));
  }

  // ── DNS findings ──────────────────────────────────────────────────────────
  children.push(sectionHeading('DNS Security Findings', HeadingLevel.HEADING_2));
  children.push(spacer(4));

  // Severity count bar
  const sevCounts = {};
  for (const f of findings) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  children.push(new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [1872, 1872, 1872, 1872, 1872],
    borders: ALL_BORDERS,
    rows: [new TableRow({ children: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s => {
      const k = s.toLowerCase();
      const style = SEV_STYLE[k];
      return cell([
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: String(sevCounts[k] || 0), bold: true, size: 40, color: style.text, font: 'Arial' })], spacing: { after: 0 } }),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: s, size: 14, color: style.text, font: 'Arial' })], spacing: { after: 0 } }),
      ], { width: 1872, bg: style.bg });
    })})],
  }));
  children.push(spacer(12));

  // Individual DNS findings (same format as TLS findings)
  for (const f of sorted) {
    if (f.severity === 'info') continue; // skip info items to keep report concise
    const style = SEV_STYLE[f.severity] || SEV_STYLE.info;
    children.push(
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1400, CONTENT_WIDTH - 1400],
        borders: NO_BORDERS,
        rows: [new TableRow({ children: [
          cell(style.label, { width: 1400, bg: style.text, color: COLOURS.white, bold: true, fontSize: 18, borders: NO_BORDERS }),
          cell(f.title,     { width: CONTENT_WIDTH - 1400, bg: style.bg, color: style.text, bold: true, fontSize: 18, borders: NO_BORDERS }),
        ]})],
      }),
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1800, CONTENT_WIDTH - 1800],
        borders: ALL_BORDERS,
        rows: [
          ...(f.hostname ? [new TableRow({ children: [
            cell('Host',   { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.hostname, { width: CONTENT_WIDTH - 1800, fontSize: 18 }),
          ]})] : []),
          new TableRow({ children: [
            cell('Area',   { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell((f.area || '').replace(/-/g, ' ').toUpperCase(), { width: CONTENT_WIDTH - 1800, fontSize: 18 }),
          ]}),
          new TableRow({ children: [
            cell('Detail', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell([new Paragraph({ children: [new TextRun({ text: f.detail, size: 18, font: 'Arial' })], spacing: { after: 0 } })], { width: CONTENT_WIDTH - 1800 }),
          ]}),
          ...(f.recommendation ? [new TableRow({ children: [
            cell('Recommendation', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell([new Paragraph({ children: [new TextRun({ text: f.recommendation, size: 18, font: 'Arial', color: COLOURS.ok, bold: true })], spacing: { after: 0 } })], { width: CONTENT_WIDTH - 1800 }),
          ]})] : []),
          ...(f.nistRef ? [new TableRow({ children: [
            cell('NIST Reference', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.nistRef, { width: CONTENT_WIDTH - 1800, fontSize: 16 }),
          ]})] : []),
          ...(f.priority ? [new TableRow({ children: [
            cell('Priority', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.priority, { width: CONTENT_WIDTH - 1800, bold: true, color: f.priority === 'P1' ? COLOURS.danger : COLOURS.warn, fontSize: 18 }),
          ]})] : []),
        ],
      }),
      spacer(10),
    );
  }

  return children;
}

function buildPriorityRows(summary, findings, dnsData, httpData, networkData) {
  const ds  = dnsData?.report?.summary     || {};
  const hs  = httpData?.summary            || {};
  const ns  = networkData?.summary         || {};

  const areas = [
    { area: 'TLS key exchange — PQ readiness',        status: 'Live',    impact: 'High',      priority: 'P1 — Immediate',  impactCol: COLOURS.danger },
    { area: 'Certificate authority posture',           status: 'Live',    impact: 'Medium',    priority: 'P2 — Near-term',  impactCol: COLOURS.warn },
    { area: 'SNI / certificate matching',             status: summary.sniMismatches?.length > 0 ? 'Finding' : 'Clear', impact: 'Medium', priority: summary.sniMismatches?.length > 0 ? 'P1 — Immediate' : 'None', impactCol: COLOURS.warn },
    { area: 'HTTP security headers',                  status: hs.missingHSTS > 0 || hs.missingCSP > 0 ? 'Findings' : httpData ? 'Clear' : 'Not tested', impact: hs.missingHSTS > 0 ? 'High' : 'Low', priority: hs.missingHSTS > 0 ? 'P1 — Immediate' : hs.missingCSP > 0 ? 'P2 — Near-term' : 'None', impactCol: hs.missingHSTS > 0 ? COLOURS.danger : COLOURS.warn },
    { area: 'CORS misconfiguration',                  status: hs.corsIssues > 0 ? `${hs.corsIssues} issue(s)` : httpData ? 'Clear' : 'Not tested', impact: hs.corsIssues > 0 ? 'High' : 'None', priority: hs.corsIssues > 0 ? 'P1 — Immediate' : 'None', impactCol: hs.corsIssues > 0 ? COLOURS.danger : COLOURS.ok },
    { area: 'DNS zone transfer (AXFR)',               status: ds.axfrVulnerable ? 'VULNERABLE' : dnsData ? 'Clear' : 'Not tested', impact: ds.axfrVulnerable ? 'Critical' : 'None', priority: ds.axfrVulnerable ? 'P1 — Immediate' : 'None', impactCol: ds.axfrVulnerable ? COLOURS.danger : COLOURS.ok },
    { area: 'Email authentication (SPF/DKIM/DMARC)',  status: (!ds.spfPresent || !ds.dmarcPolicy) ? 'Finding' : ds.dmarcPolicy === 'reject' ? 'Clear' : 'Partial', impact: (!ds.spfPresent || !ds.dmarcPolicy) ? 'High' : 'Low', priority: (!ds.spfPresent || !ds.dmarcPolicy) ? 'P1 — Immediate' : 'P2 — Near-term', impactCol: (!ds.spfPresent) ? COLOURS.danger : COLOURS.warn },
    { area: 'DNSSEC',                                 status: ds.dnssecDeployed ? 'Deployed' : dnsData ? 'Not deployed' : 'Not tested', impact: ds.dnssecDeployed ? 'None' : 'Medium', priority: ds.dnssecDeployed ? 'None' : 'P2 — Near-term', impactCol: ds.dnssecDeployed ? COLOURS.ok : COLOURS.warn },
    { area: 'Subdomain takeover risk',                status: ds.takeoverCount > 0 ? `${ds.takeoverCount} vulnerable` : ds.danglingCNAMECount > 0 ? `${ds.danglingCNAMECount} dangling` : dnsData ? 'Clear' : 'Not tested', impact: ds.takeoverCount > 0 ? 'Critical' : ds.danglingCNAMECount > 0 ? 'High' : 'None', priority: ds.takeoverCount > 0 ? 'P1 — Immediate' : ds.danglingCNAMECount > 0 ? 'P1 — Immediate' : 'None', impactCol: ds.takeoverCount > 0 ? COLOURS.danger : COLOURS.ok },
    { area: 'CAA records',                            status: ds.caaPresent ? 'Present' : dnsData ? 'Missing' : 'Not tested', impact: ds.caaPresent ? 'None' : 'Medium', priority: ds.caaPresent ? 'None' : 'P2 — Near-term', impactCol: ds.caaPresent ? COLOURS.ok : COLOURS.warn },
    { area: 'SSH post-quantum readiness',             status: ns.sshHostsScanned > 0 ? (ns.sshPQReady === ns.sshHostsScanned ? 'All hosts ready' : `${ns.sshPQReady}/${ns.sshHostsScanned} ready`) : networkData ? 'No SSH found' : 'Not tested', impact: ns.sshHostsScanned > 0 && ns.sshPQReady < ns.sshHostsScanned ? 'High' : 'None', priority: ns.sshHostsScanned > 0 && ns.sshPQReady < ns.sshHostsScanned ? 'P1 — Immediate' : 'None', impactCol: ns.sshPQReady < ns.sshHostsScanned ? COLOURS.danger : COLOURS.ok },
    { area: 'Critical services exposed (ports)',      status: ns.criticalPorts > 0 ? `${ns.criticalPorts} critical port(s)` : networkData ? 'Clear' : 'Not tested', impact: ns.criticalPorts > 0 ? 'Critical' : 'None', priority: ns.criticalPorts > 0 ? 'P1 — Immediate' : 'None', impactCol: ns.criticalPorts > 0 ? COLOURS.danger : COLOURS.ok },
    { area: 'SMTP STARTTLS enforcement',              status: ns.smtpHostsScanned > 0 ? (ns.smtpStartTLS === ns.smtpHostsScanned ? 'All enforced' : 'Issues found') : networkData ? 'No SMTP found' : 'Not tested', impact: ns.smtpHostsScanned > 0 && ns.smtpStartTLS < ns.smtpHostsScanned ? 'Medium' : 'None', priority: 'None', impactCol: COLOURS.warn },
    { area: 'Cookie security flags',                  status: hs.cookieIssues > 0 ? `${hs.cookieIssues} issue(s)` : httpData ? 'Clear' : 'Not tested', impact: hs.cookieIssues > 0 ? 'Medium' : 'None', priority: hs.cookieIssues > 0 ? 'P2 — Near-term' : 'None', impactCol: hs.cookieIssues > 0 ? COLOURS.warn : COLOURS.ok },
    { area: 'Externally exposed dev infrastructure',  status: summary.devHostsExposed?.length > 0 ? 'Finding' : 'Clear', impact: summary.devHostsExposed?.length > 0 ? 'Medium' : 'None', priority: summary.devHostsExposed?.length > 0 ? 'P1 — Immediate' : 'None', impactCol: COLOURS.warn },
    { area: 'DNS surface / dormant subdomains',       status: summary.hostsUnreachable > 0 ? 'Finding' : 'Clear', impact: 'Low–Medium', priority: summary.hostsUnreachable > 0 ? 'P2 — Near-term' : 'None', impactCol: COLOURS.ok },
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

// ─── CBOM Board Metrics Section ───────────────────────────────────────────────

function buildCBOMSection(m) {
  if (!m) return [];

  const qeiColour = m.quantumExposureIndex >= 70 ? COLOURS.danger
                  : m.quantumExposureIndex >= 40 ? COLOURS.warn
                  : COLOURS.ok;

  const colW = [3500, 3000, 2860];
  return [
    sectionHeading('CBOM Board Metrics'),
    bodyText(
      `The Cryptographic Bill of Materials (CBOM) dashboard provides a longitudinal view of cryptographic posture ` +
      `across ${m.totalScans || 1} scan(s) of this domain. The Quantum Exposure Index (QEI) is a composite score ` +
      `(0–100, lower is better) derived from PQ readiness, HNDL risk, and finding severity.`
    ),
    spacer(8),

    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [CONTENT_WIDTH / 2, CONTENT_WIDTH / 2],
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          cell([
            new Paragraph({ alignment: AlignmentType.CENTER, children: [
              new TextRun({ text: String(m.quantumExposureIndex ?? '—'), bold: true, size: 72, color: qeiColour, font: 'Arial' }),
            ], spacing: { after: 0 } }),
            new Paragraph({ alignment: AlignmentType.CENTER, children: [
              new TextRun({ text: 'QUANTUM EXPOSURE INDEX', size: 14, color: COLOURS.midGrey, font: 'Arial' }),
            ], spacing: { after: 0 } }),
          ], { width: CONTENT_WIDTH / 2, bg: COLOURS.lightGrey }),
          cell([
            new Paragraph({ alignment: AlignmentType.CENTER, children: [
              new TextRun({ text: String(m.cryptographicDebt?.openFindings ?? '—'), bold: true, size: 72, color: COLOURS.navy, font: 'Arial' }),
            ], spacing: { after: 0 } }),
            new Paragraph({ alignment: AlignmentType.CENTER, children: [
              new TextRun({ text: `OPEN FINDINGS  ·  ~${m.cryptographicDebt?.estimatedEffortDays ?? '?'} engineer-days`, size: 14, color: COLOURS.midGrey, font: 'Arial' }),
            ], spacing: { after: 0 } }),
          ], { width: CONTENT_WIDTH / 2, bg: COLOURS.lightGrey }),
        ]}),
      ],
    }),

    spacer(8),

    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: colW,
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [
          headerCell('Asset',                colW[0]),
          headerCell('Value',                colW[1]),
          headerCell('Detail',               colW[2]),
        ]}),
        ...([
          ['Total assets probed',  String(m.assetInventory?.total      ?? '—'), 'Unique hostnames probed in latest scan'],
          ['PQ Ready',             String(m.assetInventory?.pqReady    ?? '—'), `${m.assetInventory?.pqReadyPercent ?? 0}% of reachable hosts`],
          ['PQ None / Unknown',    `${m.assetInventory?.pqNone ?? 0} / ${m.assetInventory?.pqUnknown ?? 0}`, 'Classical ECDHE or KEX group unconfirmed'],
          ['Active waivers',       String(m.riskRegister?.activeWaivers ?? 0), 'Risk-accepted findings currently in waiver'],
          ['Reviews due (30 d)',   String(m.riskRegister?.upcomingReviews30d ?? 0), 'Waiver reviews due within 30 days'],
        ].map(([k, v, d], i) => new TableRow({ children: [
          cell(k, { width: colW[0], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: true,  fontSize: 18 }),
          cell(v, { width: colW[1], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
          cell(d, { width: colW[2], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 16, color: COLOURS.midGrey }),
        ]}))),
      ],
    }),
    spacer(8),
  ];
}

// ─── Code / SCA Section ───────────────────────────────────────────────────────

function buildCodeScanSection(codeData) {
  if (!codeData?.findings) return [];

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted   = [...codeData.findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const children = [
    sectionHeading('Internal Code / SCA Scan'),
    bodyText(
      `Static source analysis was performed on ${codeData.filesScanned} file(s) under ${codeData.rootPath}. ` +
      `${sorted.length} finding(s) were identified covering cryptographic API usage, hardcoded secrets, ` +
      `dependency version pinning, and TLS configuration patterns.`
    ),
    spacer(6),
  ];

  if (sorted.length === 0) {
    children.push(bodyText('No code / SCA findings identified.'));
    return children;
  }

  const colW = [1600, 1200, 2800, 3760];
  children.push(new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: colW,
    borders: ALL_BORDERS,
    rows: [
      new TableRow({ children: [
        headerCell('Severity', colW[0]),
        headerCell('File',     colW[1]),
        headerCell('Finding',  colW[2]),
        headerCell('Detail',   colW[3]),
      ]}),
      ...sorted.map((f, i) => {
        const style = SEV_STYLE[f.severity] || SEV_STYLE.info;
        return new TableRow({ children: [
          cell(style.label,  { width: colW[0], bg: style.bg, color: style.text, bold: true, fontSize: 16 }),
          cell(`${f.file || ''}${f.line ? `:${f.line}` : ''}`, { width: colW[1], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 14 }),
          cell(f.name || f.title, { width: colW[2], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: true, fontSize: 16 }),
          cell(f.recommendation || f.detail || '', { width: colW[3], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 16 }),
        ]});
      }),
    ],
  }));

  return [...children, spacer(8)];
}

// ─── PKI Scan Section ─────────────────────────────────────────────────────────

function buildPKIScanSection(pkiData) {
  if (!pkiData?.findings) return [];

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const sorted   = [...pkiData.findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));

  const children = [
    sectionHeading('Internal PKI / Certificate Scan'),
    bodyText(
      `${pkiData.certificatesParsed} certificate(s) were parsed from ${pkiData.filesScanned} file(s) under ${pkiData.rootPath}. ` +
      `Certificates were assessed for expiry, key strength, and post-quantum migration readiness.`
    ),
    spacer(6),
  ];

  if (sorted.length === 0) {
    children.push(bodyText('No PKI findings identified.'));
    return children;
  }

  for (const f of sorted) {
    const style = SEV_STYLE[f.severity] || SEV_STYLE.info;
    children.push(
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1400, CONTENT_WIDTH - 1400],
        borders: NO_BORDERS,
        rows: [new TableRow({ children: [
          cell(style.label, { width: 1400, bg: style.text, color: COLOURS.white, bold: true, fontSize: 18, borders: NO_BORDERS }),
          cell(f.title,     { width: CONTENT_WIDTH - 1400, bg: style.bg, color: style.text, bold: true, fontSize: 18, borders: NO_BORDERS }),
        ]})],
      }),
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [1800, CONTENT_WIDTH - 1800],
        borders: ALL_BORDERS,
        rows: [
          new TableRow({ children: [
            cell('File',           { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.file || '—',    { width: CONTENT_WIDTH - 1800, fontSize: 18 }),
          ]}),
          new TableRow({ children: [
            cell('Detail',         { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.detail,         { width: CONTENT_WIDTH - 1800, fontSize: 18 }),
          ]}),
          ...(f.recommendation ? [new TableRow({ children: [
            cell('Recommendation', { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.recommendation, { width: CONTENT_WIDTH - 1800, color: COLOURS.ok, bold: true, fontSize: 18 }),
          ]})] : []),
          ...(f.nistRef ? [new TableRow({ children: [
            cell('NIST Ref',       { width: 1800, bg: COLOURS.lightGrey, bold: true, fontSize: 18 }),
            cell(f.nistRef,        { width: CONTENT_WIDTH - 1800, fontSize: 16 }),
          ]})] : []),
        ],
      }),
      spacer(6),
    );
  }

  return [...children, spacer(8)];
}

// ─── Vendor Scorecard Section ─────────────────────────────────────────────────

function buildVendorSection(vendorData) {
  if (!vendorData?.vendor || !vendorData?.scorecard) return [];

  const { vendor, scorecard } = vendorData;
  const gradeColour = { A: COLOURS.ok, B: COLOURS.ok, C: COLOURS.warn, D: COLOURS.danger, F: COLOURS.danger };
  const colour      = gradeColour[scorecard.grade] || COLOURS.navy;

  const catLabels = {
    pqReadiness:     'PQ / TLS Readiness (max 25)',
    emailSecurity:   'Email Security (max 20)',
    webSecurity:     'Web Security (max 20)',
    networkExposure: 'Network Exposure (max 20)',
    certHygiene:     'Certificate Hygiene (max 15)',
  };

  const colW = [3500, 2000, 3860];

  return [
    sectionHeading('Vendor Security Scorecard'),
    bodyText(
      `An automated technical assessment was performed against ${vendor.name} (${vendor.domain}) ` +
      `on ${new Date(vendor.assessedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}. ` +
      `The scorecard measures externally-observable security posture across five categories.`
    ),
    spacer(8),

    // Grade card + category breakdown side-by-side
    ...Object.entries(scorecard.categoryScores).map(([cat, score], i) => {
      const grade = scorecard.categoryGrades[cat];
      const gc    = gradeColour[grade] || COLOURS.navy;
      return new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: [2000, CONTENT_WIDTH - 3000, 1000],
        borders: ALL_BORDERS,
        rows: [new TableRow({ children: [
          ...(i === 0 ? [cell([
            new Paragraph({ alignment: AlignmentType.CENTER, children: [
              new TextRun({ text: scorecard.grade, bold: true, size: 96, color: colour, font: 'Arial' }),
            ], spacing: { after: 0 } }),
            new Paragraph({ alignment: AlignmentType.CENTER, children: [
              new TextRun({ text: `${scorecard.overallScore} / 100`, size: 20, color: COLOURS.midGrey, font: 'Arial' }),
            ], spacing: { after: 0 } }),
          ], { width: 2000, bg: COLOURS.lightGrey })] : [
            cell('', { width: 2000, bg: COLOURS.lightGrey }),
          ]),
          cell(catLabels[cat] || cat, { width: CONTENT_WIDTH - 3000, bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 18 }),
          cell(`${grade}  (${score})`,  { width: 1000,               bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, bold: true, color: gc, fontSize: 18 }),
        ]})],
      });
    }),

    spacer(8),

    ...(scorecard.topConcerns?.length > 0 ? [
      new Paragraph({ children: [new TextRun({ text: 'Top Concerns', bold: true, size: 22, color: COLOURS.navy, font: 'Arial' })], spacing: { before: 80, after: 80 } }),
      new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: colW,
        borders: ALL_BORDERS,
        rows: [
          new TableRow({ children: [
            headerCell('Severity', colW[0]),
            headerCell('Host',     colW[1]),
            headerCell('Finding',  colW[2]),
          ]}),
          ...scorecard.topConcerns.slice(0, 8).map((f, i) => {
            const style = SEV_STYLE[f.severity] || SEV_STYLE.info;
            return new TableRow({ children: [
              cell(style.label,  { width: colW[0], bg: style.bg, color: style.text, bold: true, fontSize: 16 }),
              cell(f.hostname || '—', { width: colW[1], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 16 }),
              cell(f.title,      { width: colW[2], bg: i % 2 === 0 ? COLOURS.white : COLOURS.lightGrey, fontSize: 16 }),
            ]});
          }),
        ],
      }),
    ] : []),

    spacer(8),
  ];
}

// ─── Main generator ───────────────────────────────────────────────────────────

// ─── HTTP Security Section ────────────────────────────────────────────────────

function buildHTTPSection(httpData) {
  if (!httpData?.findings) return [];
  const { findings, summary } = httpData;
  const sevOrder = ['critical','high','medium','low','info'];
  const sorted = [...findings].sort((a,b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  const nonInfo = sorted.filter(f => f.severity !== 'info');

  const children = [
    sectionHeading('HTTP Security Assessment'),
    bodyText(
      `This section presents the results of the HTTP security assessment, covering security response headers, CORS policy, ` +
      `cookie security flags, permitted HTTP methods, redirect chain integrity, and API exposure.`
    ),
    spacer(8),

    // Overview table
    sectionHeading('HTTP Security Posture Overview', HeadingLevel.HEADING_2),
    spacer(4),
    new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: [3200, 1800, 2160, 2200],
      borders: ALL_BORDERS,
      rows: [
        new TableRow({ children: [headerCell('CHECK',3200), headerCell('STATUS',1800), headerCell('HOSTS AFFECTED',2160), headerCell('ACTION',2200)] }),
        ...[
          { check: 'HSTS (Strict-Transport-Security)', status: summary.missingHSTS > 0 ? 'Issues found' : 'Clear', affected: summary.missingHSTS, action: summary.missingHSTS > 0 ? 'Add max-age≥31536000; includeSubDomains' : 'No action', col: summary.missingHSTS > 0 ? COLOURS.danger : COLOURS.ok },
          { check: 'Content-Security-Policy', status: summary.missingCSP > 0 ? 'Missing/weak' : 'Clear', affected: summary.missingCSP, action: summary.missingCSP > 0 ? "Add default-src 'self'; object-src 'none'" : 'No action', col: summary.missingCSP > 0 ? COLOURS.danger : COLOURS.ok },
          { check: 'CORS configuration', status: summary.corsIssues > 0 ? `${summary.corsIssues} misconfiguration(s)` : 'Clear', affected: summary.corsIssues, action: summary.corsIssues > 0 ? 'Restrict to explicit allowlist' : 'No action', col: summary.corsIssues > 0 ? COLOURS.danger : COLOURS.ok },
          { check: 'Cookie security flags', status: summary.cookieIssues > 0 ? `${summary.cookieIssues} insecure cookie(s)` : 'Clear', affected: summary.cookieIssues, action: summary.cookieIssues > 0 ? 'Add Secure; HttpOnly; SameSite=Strict' : 'No action', col: summary.cookieIssues > 0 ? COLOURS.warn : COLOURS.ok },
          { check: 'Server version disclosure', status: summary.serverDisclosure?.length > 0 ? 'Disclosing' : 'Clear', affected: summary.serverDisclosure?.length || 0, action: 'Remove Server / X-Powered-By headers', col: summary.serverDisclosure?.length > 0 ? COLOURS.warn : COLOURS.ok },
          { check: 'HTTP TRACE method', status: summary.traceEnabled ? 'ENABLED' : 'Disabled', affected: summary.traceEnabled ? 1 : 0, action: summary.traceEnabled ? 'Disable TRACE immediately' : 'No action', col: summary.traceEnabled ? COLOURS.warn : COLOURS.ok },
          { check: 'GraphQL introspection', status: summary.graphqlExposed ? 'EXPOSED' : 'Not detected', affected: summary.graphqlExposed ? 1 : 0, action: summary.graphqlExposed ? 'Disable in production' : 'No action', col: summary.graphqlExposed ? COLOURS.warn : COLOURS.ok },
        ].map((r,i) => new TableRow({ children: [
          cell(r.check,    {width:3200, bg: i%2===0?COLOURS.white:COLOURS.lightGrey, bold:true, fontSize:18}),
          cell(r.status,   {width:1800, bg: i%2===0?COLOURS.white:COLOURS.lightGrey, color:r.col, bold:r.affected>0, fontSize:18}),
          cell(String(r.affected||'—'), {width:2160, bg: i%2===0?COLOURS.white:COLOURS.lightGrey, fontSize:18}),
          cell(r.action,   {width:2200, bg: i%2===0?COLOURS.white:COLOURS.lightGrey, fontSize:16}),
        ]})),
      ],
    }),
    spacer(12),

    // Findings
    sectionHeading('HTTP Security Findings', HeadingLevel.HEADING_2),
    spacer(4),
  ];

  // Severity bar
  const sevCounts = {};
  for (const f of findings) sevCounts[f.severity] = (sevCounts[f.severity]||0)+1;
  children.push(new Table({
    width:{size:CONTENT_WIDTH,type:WidthType.DXA},columnWidths:[1872,1872,1872,1872,1872],borders:ALL_BORDERS,
    rows:[new TableRow({children:['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s=>{
      const k=s.toLowerCase(); const style=SEV_STYLE[k];
      return cell([
        new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:String(sevCounts[k]||0),bold:true,size:40,color:style.text,font:'Arial'})],spacing:{after:0}}),
        new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:s,size:14,color:style.text,font:'Arial'})],spacing:{after:0}}),
      ],{width:1872,bg:style.bg});
    })})],
  }));
  children.push(spacer(12));

  for (const f of nonInfo) {
    const style = SEV_STYLE[f.severity] || SEV_STYLE.info;
    children.push(
      new Table({width:{size:CONTENT_WIDTH,type:WidthType.DXA},columnWidths:[1400,CONTENT_WIDTH-1400],borders:NO_BORDERS,
        rows:[new TableRow({children:[
          cell(style.label,{width:1400,bg:style.text,color:COLOURS.white,bold:true,fontSize:18,borders:NO_BORDERS}),
          cell(f.title,{width:CONTENT_WIDTH-1400,bg:style.bg,color:style.text,bold:true,fontSize:18,borders:NO_BORDERS}),
        ]})]}),
      new Table({width:{size:CONTENT_WIDTH,type:WidthType.DXA},columnWidths:[1800,CONTENT_WIDTH-1800],borders:ALL_BORDERS,
        rows:[
          ...(f.hostname?[new TableRow({children:[cell('Host',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell(f.hostname,{width:CONTENT_WIDTH-1800,fontSize:18})]})]:[]),
          new TableRow({children:[cell('Area',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell((f.area||'').replace(/-/g,' ').toUpperCase(),{width:CONTENT_WIDTH-1800,fontSize:18})]}),
          new TableRow({children:[cell('Detail',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell([new Paragraph({children:[new TextRun({text:f.detail,size:18,font:'Arial'})],spacing:{after:0}})],{width:CONTENT_WIDTH-1800})]}),
          ...(f.recommendation?[new TableRow({children:[cell('Recommendation',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell([new Paragraph({children:[new TextRun({text:f.recommendation,size:18,font:'Arial',color:COLOURS.ok,bold:true})],spacing:{after:0}})],{width:CONTENT_WIDTH-1800})]})]:[]),
          ...(f.nistRef?[new TableRow({children:[cell('NIST Reference',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell(f.nistRef,{width:CONTENT_WIDTH-1800,fontSize:16})]})]:[]),
        ]}),
      spacer(10),
    );
  }
  return children;
}

// ─── Network Security Section ─────────────────────────────────────────────────

function buildNetworkSection(networkData) {
  if (!networkData?.findings) return [];
  const { findings, summary, report } = networkData;
  const sevOrder = ['critical','high','medium','low','info'];
  const sorted = [...findings].sort((a,b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  const nonInfo = sorted.filter(f => f.severity !== 'info');

  const children = [
    sectionHeading('Network & Protocol Security Assessment'),
    bodyText(
      `This section covers the results of port scanning, SSH post-quantum readiness assessment, SMTP STARTTLS analysis, and ` +
      `IPv6 surface review conducted against the externally-facing infrastructure.`
    ),
    spacer(8),

    // Port scan overview
    sectionHeading('Open Ports Discovered', HeadingLevel.HEADING_2),
    spacer(4),
  ];

  // Build port table from all scans
  const allOpenPorts = (report?.portScans || []).flatMap(s =>
    s.openPorts.map(p => ({ ...p, hostname: s.hostname, ip: s.ip }))
  );

  if (allOpenPorts.length === 0) {
    children.push(bodyText('No unexpected open ports detected beyond standard web ports (80, 443).'));
  } else {
    children.push(new Table({
      width:{size:CONTENT_WIDTH,type:WidthType.DXA},
      columnWidths:[2400,900,1200,1500,3360],borders:ALL_BORDERS,
      rows:[
        new TableRow({children:[headerCell('Hostname',2400),headerCell('Port',900),headerCell('Protocol',1200),headerCell('Severity',1500),headerCell('Assessment',3360)]}),
        ...allOpenPorts.slice(0,30).map((p,i)=>{
          const def = {severity:'info',note:'Service detected'};
          const col = p.severity==='critical'?COLOURS.danger:p.severity==='high'?COLOURS.warn:COLOURS.ok;
          const bg = i%2===0?COLOURS.white:COLOURS.lightGrey;
          return new TableRow({children:[
            cell(p.hostname,{width:2400,bg,fontSize:16}),
            cell(String(p.port),{width:900,bg,fontSize:18,bold:true}),
            cell(p.proto,{width:1200,bg,fontSize:16}),
            cell((p.severity||'info').toUpperCase(),{width:1500,bg:bg,color:col,bold:true,fontSize:16}),
            cell(p.note||'Open',{width:3360,bg,fontSize:16}),
          ]});
        }),
      ],
    }));
  }

  children.push(spacer(12));

  // SSH summary
  if (report?.sshScans?.length > 0) {
    children.push(sectionHeading('SSH Security Analysis', HeadingLevel.HEADING_2));
    children.push(spacer(4));
    children.push(new Table({
      width:{size:CONTENT_WIDTH,type:WidthType.DXA},
      columnWidths:[2800,2000,1500,3060],borders:ALL_BORDERS,
      rows:[
        new TableRow({children:[headerCell('Host',2800),headerCell('Banner',2000),headerCell('PQ KEX',1500),headerCell('Key Findings',3060)]}),
        ...report.sshScans.map((s,i)=>{
          const hasPQ = s.findings.some(f=>f.id==='SSH-PQ-KEX-PRESENT');
          const bg = i%2===0?COLOURS.white:COLOURS.lightGrey;
          const issues = s.findings.filter(f=>f.severity!=='info').map(f=>f.title.slice(0,50)).slice(0,2).join('; ') || 'None';
          return new TableRow({children:[
            cell(s.hostname,{width:2800,bg,fontSize:16}),
            cell((s.banner||'Unknown').slice(0,30),{width:2000,bg,fontSize:14}),
            cell(hasPQ?'YES':'NO',{width:1500,bg,color:hasPQ?COLOURS.ok:COLOURS.danger,bold:true,fontSize:18}),
            cell(issues,{width:3060,bg,fontSize:14}),
          ]});
        }),
      ],
    }));
    children.push(spacer(12));
  }

  // SMTP summary
  if (report?.smtpScans?.length > 0) {
    children.push(sectionHeading('SMTP STARTTLS Analysis', HeadingLevel.HEADING_2));
    children.push(spacer(4));
    children.push(new Table({
      width:{size:CONTENT_WIDTH,type:WidthType.DXA},
      columnWidths:[2400,900,1800,1500,2760],borders:ALL_BORDERS,
      rows:[
        new TableRow({children:[headerCell('Host',2400),headerCell('Port',900),headerCell('STARTTLS',1800),headerCell('TLS Version',1500),headerCell('Assessment',2760)]}),
        ...report.smtpScans.map((s,i)=>{
          const bg=i%2===0?COLOURS.white:COLOURS.lightGrey;
          return new TableRow({children:[
            cell(s.hostname,{width:2400,bg,fontSize:16}),
            cell(String(s.port),{width:900,bg,fontSize:16}),
            cell(s.starttls?'YES':'NO',{width:1800,bg,color:s.starttls?COLOURS.ok:COLOURS.danger,bold:true,fontSize:18}),
            cell(s.tls?.protocol||'—',{width:1500,bg,fontSize:16}),
            cell(s.findings.filter(f=>f.severity!=='info').map(f=>f.title.slice(0,40)).join('; ')||'OK',{width:2760,bg,fontSize:14}),
          ]});
        }),
      ],
    }));
    children.push(spacer(12));
  }

  // Network findings
  children.push(sectionHeading('Network Security Findings', HeadingLevel.HEADING_2));
  children.push(spacer(4));

  const sevCounts={};
  for (const f of findings) sevCounts[f.severity]=(sevCounts[f.severity]||0)+1;
  children.push(new Table({
    width:{size:CONTENT_WIDTH,type:WidthType.DXA},columnWidths:[1872,1872,1872,1872,1872],borders:ALL_BORDERS,
    rows:[new TableRow({children:['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s=>{
      const k=s.toLowerCase();const style=SEV_STYLE[k];
      return cell([
        new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:String(sevCounts[k]||0),bold:true,size:40,color:style.text,font:'Arial'})],spacing:{after:0}}),
        new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:s,size:14,color:style.text,font:'Arial'})],spacing:{after:0}}),
      ],{width:1872,bg:style.bg});
    })})],
  }));
  children.push(spacer(12));

  for (const f of nonInfo) {
    const style=SEV_STYLE[f.severity]||SEV_STYLE.info;
    children.push(
      new Table({width:{size:CONTENT_WIDTH,type:WidthType.DXA},columnWidths:[1400,CONTENT_WIDTH-1400],borders:NO_BORDERS,
        rows:[new TableRow({children:[
          cell(style.label,{width:1400,bg:style.text,color:COLOURS.white,bold:true,fontSize:18,borders:NO_BORDERS}),
          cell(f.title,{width:CONTENT_WIDTH-1400,bg:style.bg,color:style.text,bold:true,fontSize:18,borders:NO_BORDERS}),
        ]})]}),
      new Table({width:{size:CONTENT_WIDTH,type:WidthType.DXA},columnWidths:[1800,CONTENT_WIDTH-1800],borders:ALL_BORDERS,
        rows:[
          ...(f.hostname?[new TableRow({children:[cell('Host',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell(f.hostname,{width:CONTENT_WIDTH-1800,fontSize:18})]})]:[]),
          new TableRow({children:[cell('Area',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell((f.area||'').replace(/-/g,' ').toUpperCase(),{width:CONTENT_WIDTH-1800,fontSize:18})]}),
          new TableRow({children:[cell('Detail',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell([new Paragraph({children:[new TextRun({text:f.detail,size:18,font:'Arial'})],spacing:{after:0}})],{width:CONTENT_WIDTH-1800})]}),
          ...(f.recommendation?[new TableRow({children:[cell('Recommendation',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell([new Paragraph({children:[new TextRun({text:f.recommendation,size:18,font:'Arial',color:COLOURS.ok,bold:true})],spacing:{after:0}})],{width:CONTENT_WIDTH-1800})]})]:[]),
          ...(f.nistRef?[new TableRow({children:[cell('NIST Reference',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell(f.nistRef,{width:CONTENT_WIDTH-1800,fontSize:16})]})]:[]),
          ...(f.priority?[new TableRow({children:[cell('Priority',{width:1800,bg:COLOURS.lightGrey,bold:true,fontSize:18}),cell(f.priority,{width:CONTENT_WIDTH-1800,bold:true,color:f.priority==='P1'?COLOURS.danger:COLOURS.warn,fontSize:18})]})]:[]),
        ]}),
      spacer(10),
    );
  }
  return children;
}

async function generateReport(
  scanResult,
  dnsData      = null,
  httpData     = null,
  networkData  = null,
  boardMetrics = null,
  codeData     = null,
  pkiData      = null,
  vendorData   = null,
) {
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
        ...buildExecutiveSummary(summary, findings, dnsData, httpData, networkData),
        ...(boardMetrics ? buildCBOMSection(boardMetrics)  : []),
        ...buildFindings(findings),
        ...(dnsData     ? buildDNSSection(dnsData)         : []),
        ...(httpData    ? buildHTTPSection(httpData)        : []),
        ...(networkData ? buildNetworkSection(networkData)  : []),
        ...(codeData    ? buildCodeScanSection(codeData)   : []),
        ...(pkiData     ? buildPKIScanSection(pkiData)     : []),
        ...(vendorData  ? buildVendorSection(vendorData)   : []),
        ...buildHostInventory(hosts),
        ...buildRoadmap(summary),
        ...buildControlMapping(),
      ],
    }],
  });

  const buffer = await Packer.toBuffer(doc);

  // docx-js generates fontTable.xml but omits it from document.xml.rels.
  // Inject the missing relationship so Word/LibreOffice don't report corruption.
  try {
    const AdmZip = (() => { try { return require('adm-zip'); } catch { return null; } })();
    if (AdmZip) {
      const zip = new AdmZip(buffer);
      const relsPath = 'word/_rels/document.xml.rels';
      const relsEntry = zip.getEntry(relsPath);
      if (relsEntry) {
        let relsXml = relsEntry.getData().toString('utf8');
        if (relsXml.includes('fontTable.xml') === false && relsXml.includes('</Relationships>')) {
          const nextId = (relsXml.match(/Id="rId(\d+)"/g) || []).length + 1;
          relsXml = relsXml.replace(
            '</Relationships>',
            `  <Relationship Id="rId${nextId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>\n</Relationships>`
          );
          zip.updateFile(relsPath, Buffer.from(relsXml, 'utf8'));
        }
      }
      return zip.toBuffer();
    }
  } catch {}

  return buffer;
}

module.exports = { generateReport };
