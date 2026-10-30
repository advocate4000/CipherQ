#!/usr/bin/env node
/* ═══════════════════════════════════════════════════════════════════════
   CipherQ — QEA build to PDF, with a numbered contents page

     node make-pdf.js scan-example.json "Client QEA"

   Two passes. The contents page needs page numbers; page numbers are only
   known once the document has been laid out; and adding the contents page
   itself shifts every page by one. So:

     pass 1  build with an unnumbered contents page (correct page count)
     render  convert to PDF, read which page each section heading landed on
     pass 2  rebuild with those numbers — the contents page is already
             present and one page long, so the pagination does not move

   The numbers are therefore measured, not assumed. If they cannot be
   measured the contents page is emitted without them, which is honest;
   a stale number is worse than no number.

   Needs LibreOffice (soffice) and poppler (pdftotext) on PATH. Without
   them, run build-qta.js directly and export the PDF from Word.
   ═══════════════════════════════════════════════════════════════════════ */

const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DATA = process.argv[2] || 'scan-example.json';
const STEM = (process.argv[3] || 'CipherQ-QEA-Example').replace(/\.(docx|pdf)$/i, '');
const DOCX = `${STEM}.docx`;
const PDF = `${STEM}.pdf`;

const have = cmd => spawnSync('which', [cmd]).status === 0;
const missing = ['soffice', 'pdftotext'].filter(c => !have(c));

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qea-'));
const SIDECAR = path.join(tmp, 'toc-pages.json');
const build = () => execFileSync('node', ['build-qta.js', DATA, DOCX], {
  stdio: 'inherit',
  env: { ...process.env, QEA_TOC_PAGES: SIDECAR, QEA_SECTIONS_OUT: path.join(tmp, 'sections.json') },
});

const render = () => {
  execFileSync('soffice', ['-env:UserInstallation=file://' + path.join(tmp, 'lo'),
    '--headless', '--convert-to', 'pdf', '--outdir', tmp, DOCX], { stdio: 'ignore' });
  return path.join(tmp, path.basename(DOCX).replace(/\.docx$/, '.pdf'));
};

if (missing.length) {
  console.log(`\n  soffice/pdftotext not found (${missing.join(', ')}).`);
  console.log('  Building the .docx with an unnumbered contents page.');
  console.log('  Export the PDF from Word: File → Export → PDF.\n');
  build();
  process.exit(0);
}

/* ── pass 1 ─────────────────────────────────────────────────────────── */
console.log('\n  pass 1 — laying out to find the page numbers');
build();
const draft = render();

const nPages = parseInt(execFileSync('pdfinfo', [draft]).toString().match(/Pages:\s+(\d+)/)[1], 10);
const pageText = [];
for (let i = 1; i <= nPages; i++) {
  pageText[i] = execFileSync('pdftotext', ['-f', String(i), '-l', String(i), draft, '-'])
    .toString().split('\n').map(l => l.trim());
}

/* The section list comes from the generator itself, written out during the
   build. Hardcoding it here would mean a new section silently missing from
   the contents. */
const TITLES = JSON.parse(fs.readFileSync(path.join(tmp, 'sections.json'), 'utf8'))
  .map(x => x.title);

/* The contents page lists every title too, so searching from page 1 would
   resolve all thirteen to the contents page itself.

   It is page 2 by construction — the cover ends in a page break and the
   contents ends in another — but assuming that silently is how a report goes
   out with a contents page numbered off by one. Verify instead: the contents
   page is the only page carrying every section title. Matching on the titles
   works where matching on a heading would not, because the headings are set
   in letter-spaced caps and text extraction inserts spaces into them. */
const contentsPage = 2;
const onContents = TITLES.filter(t => pageText[contentsPage] && pageText[contentsPage].includes(t));
if (onContents.length !== TITLES.length) {
  console.error(`\n  page ${contentsPage} is not the contents page `
    + `(${onContents.length}/${TITLES.length} titles found); aborting rather than guessing.\n`);
  process.exit(1);
}

const pages = {};
let cursor = contentsPage + 1;
for (const title of TITLES) {
  let found = 0;
  for (let i = cursor; i <= nPages; i++) {
    if (pageText[i].includes(title)) { found = i; break; }
  }
  if (!found) {
    console.error(`\n  could not locate "${title}" in the rendered PDF.`);
    console.error('  Emitting an unnumbered contents page rather than a wrong one.\n');
    fs.rmSync(tmp, { recursive: true, force: true });
    execFileSync('node', ['build-qta.js', DATA, DOCX],
      { stdio: 'inherit', env: { ...process.env, QEA_TOC_PAGES: '/nonexistent' } });
    process.exit(1);
  }
  pages[title] = found;
  cursor = found;   /* sections appear in order; never search backwards */
}

fs.writeFileSync(SIDECAR, JSON.stringify(pages, null, 2));

/* ── pass 2 ─────────────────────────────────────────────────────────── */
console.log('\n  pass 2 — rebuilding with resolved page numbers');
build();
const finalPdf = render();

/* The contents page was one page in both passes, so pagination should not
   have shifted. Verify rather than trust. */
const after = parseInt(execFileSync('pdfinfo', [finalPdf]).toString().match(/Pages:\s+(\d+)/)[1], 10);
if (after !== nPages) {
  console.error(`\n  pagination moved between passes (${nPages} → ${after}); numbers may be stale.\n`);
  process.exit(1);
}
const check = execFileSync('pdftotext', ['-f', String(pages['Sequence of work']),
  '-l', String(pages['Sequence of work']), finalPdf, '-']).toString();
if (!check.includes('Sequence of work')) {
  console.error('\n  verification failed: contents does not agree with the rendered PDF.\n');
  process.exit(1);
}

fs.copyFileSync(finalPdf, PDF);
fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\n  ${DOCX}`);
console.log(`  ${PDF}  (${after} pages, contents verified)\n`);
Object.entries(pages).forEach(([t, n]) => console.log(`    ${String(n).padStart(3)}  ${t}`));
console.log('');
