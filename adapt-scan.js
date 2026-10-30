#!/usr/bin/env node
'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   CipherQ — scanner output → QEA report input, command line

     node adapt-scan.js scan.json draft.json [--http http.json] [--profile p.json]

   The mapping lives in qea-input.js, which the platform's report endpoint
   also uses. This is the terminal front end: it writes the draft and lists
   what still needs you.

   Anything a scan cannot observe is left as a TODO and build-qta.js refuses
   to build while one remains. Four things are never observable:

     retention      How long the client must keep the data confidential.
                    Worth 20 of the 100 index points and the basis of the
                    exposure window. Client-attested.
     authorisation  The engagement reference. Active probing without recorded
                    authority is an offence under the Computer Misuse Act
                    1990, which has no research defence.
     costs          Your rate card, not a market estimate.
     board copy     The position, the ask and the decision.

   A default for any of these is a number a client's board reads as a
   finding, so they are blanks that stop the build.
   ═══════════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const { buildInput } = require('./qea-input');

const args = process.argv.slice(2);
const flag = name => { const i = args.indexOf(name); return i === -1 ? null : args[i + 1]; };
const positional = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
const IN = positional[0];
const OUT = positional[1] || 'scan-draft.json';
if (!IN) {
  console.error('usage: node adapt-scan.js <scanner.json> [out.json] [--http h.json] [--dns d.json] [--net n.json] [--profile p.json]');
  process.exit(2);
}

const read = p => JSON.parse(fs.readFileSync(p, 'utf8'));
const scan = read(IN);
const http = flag('--http') ? read(flag('--http')) : null;
const profile = flag('--profile') ? read(flag('--profile')) : {};
const dns = flag('--dns') ? read(flag('--dns')) : null;
const net = flag('--net') ? read(flag('--net')) : null;

for (const [f, name] of [[http, '--http'], [dns, '--dns'], [net, '--net']]) {
  if (!f) console.error(`  ! no ${name} file — that layer is recorded as out of scope, not as clean.`);
}

let draft;
try {
  draft = buildInput(scan, http, profile, dns, net);   /* dns was previously read and discarded */
} catch (e) {
  if (e.code === 'NOTHING_ASSESSED') {
    console.error(`\n  ${e.message}`);
    console.error(`  ${e.detail.probed} probed, ${e.detail.unreachable} resolved without a handshake.`);
    console.error('  Check scope, DNS and network path, then re-scan.\n');
    process.exit(1);
  }
  throw e;
}

fs.writeFileSync(OUT, JSON.stringify(draft, null, 2));

const todos = [];
(function walk(node, path) {
  if (typeof node === 'string') { if (node.startsWith('TODO')) todos.push(path); return; }
  if (Array.isArray(node)) return node.forEach((v, i) => walk(v, `${path}[${i}]`));
  if (node && typeof node === 'object') Object.entries(node).forEach(([k, v]) => walk(v, path ? `${path}.${k}` : k));
})(draft, '');

const a = draft.assessment;
console.log(`\n  ${OUT}`);
console.log(`  observed: ${draft.scope.hosts_reachable} reachable of ${draft.scope.hosts_probed} probed · `
  + `${draft.kex.hosts_with_pq_kex} with confirmed hybrid KEX · index ${a.qei} (${a.band})`);

if (!todos.length) {
  console.log(`\n  Complete. Build it: node make-pdf.js ${OUT} "Client QEA"\n`);
} else {
  console.log(`\n  ${todos.length} field(s) need you before this can be built:\n`);
  todos.forEach(t => console.log(`    ${t}`));
  console.log(`\n  Fill them, then: node make-pdf.js ${OUT} "Client QEA"\n`);
}
