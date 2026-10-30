#!/usr/bin/env node
'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   CipherQ — Quantum Exposure Assessment, command line

     node build-qta.js scan-example.json "Client QEA.docx"

   The document itself lives in qea-doc.js, which the platform's report
   endpoint calls directly. This wrapper is the terminal front end: it reads
   the file, prints the gate's findings if it refuses, and writes the .docx.
   ═══════════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const { build, validate } = require('./qea-doc');

const IN = process.argv[2] || 'scan-example.json';
const OUT = process.argv[3] || 'CipherQ-QEA.docx';
const TOC_SIDECAR = process.env.QEA_TOC_PAGES || 'toc-pages.json';
const SECTIONS_OUT = process.env.QEA_SECTIONS_OUT;   /* set by make-pdf.js */

const scan = JSON.parse(fs.readFileSync(IN, 'utf8'));

const check = validate(scan);
if (check.todos.length) {
  console.error(`\n  Refusing to build: ${check.todos.length} field(s) still unanswered.\n`);
  check.todos.forEach(t => console.error(`    ${t.path}\n      ${t.text}\n`));
  console.error('  These are judgements the scan cannot make. Fill them and run again.\n');
  process.exit(1);
}
if (!check.reconciles) {
  console.error(`\n  Refusing to build: components sum to ${check.reconcile.sum} `
    + `but the index is stated as ${check.reconcile.stated}.`);
  console.error('  The report prints these as a table with the index as its total row.\n');
  process.exit(1);
}

let tocPages = null;
try { tocPages = JSON.parse(fs.readFileSync(TOC_SIDECAR, 'utf8')); } catch { /* unnumbered */ }

build(scan, { tocPages }).then(({ buffer, sections, numbered }) => {
  fs.writeFileSync(OUT, buffer);
  if (SECTIONS_OUT) fs.writeFileSync(SECTIONS_OUT, JSON.stringify(sections, null, 2));

  const c = scan.client, a = scan.assessment;
  const horizon = a.assessment_year + c.data_retention_years;
  const byClass = cl => scan.exposures.filter(e => e.class === cl).length;
  console.log(`  written: ${OUT}  (${(buffer.length / 1024).toFixed(0)} KB)`);
  console.log(`  client : ${c.name}   QEI ${a.qei}/100 (${a.band})`);
  console.log(`  classes: A=${byClass('A')}  B=${byClass('B')}  C=${byClass('C')}`);
  console.log(`  window : data confidential to ${horizon}, CRQC ${a.crqc_estimate} `
    + `→ ${horizon - a.crqc_estimate}yr overrun`);
  console.log(`  contents: ${sections.length} sections, page numbers `
    + `${numbered ? 'resolved' : 'OMITTED — run make-pdf.js to number them'}`);
});
