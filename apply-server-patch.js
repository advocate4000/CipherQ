'use strict';
/* Wire the QEA report into server.js.
 *
 *   node apply-server-patch.js            # inspect and report, change nothing
 *   node apply-server-patch.js --write    # make the change, after a backup
 *
 * I have never seen your server.js, so this inspects before it edits and
 * refuses rather than guesses. Everything it does is two lines you could type
 * yourself; the value is that it tells you what it found first.
 */

const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, process.argv.find((a) => a.endsWith('.js') && a !== __filename && !a.startsWith('-')) || 'server.js');
const WRITE = process.argv.includes('--write');

if (!fs.existsSync(FILE)) {
  console.error(`\nNot found: ${FILE}`);
  console.error('Run this from the directory containing server.js, or pass a path.\n');
  process.exit(2);
}

const src = fs.readFileSync(FILE, 'utf8');
const lines = src.split('\n');
const findings = [];
const actions = [];

function note(level, msg) { findings.push([level, msg]); }

/* ── What is wired today ─────────────────────────────────────────────────── */
const usesOld = /require\(['"]\.\/report['"]\)/.test(src);
const usesQeaDoc = /require\(['"]\.\/qea-doc['"]\)/.test(src);
const usesQeaInput = /require\(['"]\.\/qea-input['"]\)/.test(src);
const usesRoute = /require\(['"]\.\/qea-route['"]\)/.test(src);
const usesDnel = /require\(['"]\.\/dnel['"]\)/.test(src);

note('info', `report.js (old generator) required: ${usesOld ? 'YES' : 'no'}`);
note('info', `qea-doc.js (new generator) required: ${usesQeaDoc ? 'YES' : 'no'}`);
note('info', `qea-input.js required: ${usesQeaInput ? 'YES' : 'no'}`);
note('info', `qea-route.js required: ${usesRoute ? 'YES' : 'no'}`);
note('info', `dnel.js required: ${usesDnel ? 'YES' : 'no'}`);

if (usesOld && !usesQeaDoc && !usesRoute) {
  note('warn', 'This server produces the OLD report format. report.js has no DNEL support, ' +
               'so no amount of deploying the QEA modules will change the document.');
}

/* ── buildInput arity — the silent one ───────────────────────────────────── */
const buildInputCalls = [];
lines.forEach((l, i) => {
  const m = l.match(/buildInput\s*\(([^;]*)/);
  if (m) buildInputCalls.push({ line: i + 1, text: l.trim(), args: m[1] });
});
for (const c of buildInputCalls) {
  const commas = (c.args.match(/,/g) || []).length;
  if (commas < 3) {
    note('error', `line ${c.line}: buildInput() called with ~${commas + 1} arguments. ` +
                  'It takes four; the fourth is networkData. Without it the report loses ' +
                  'Class D and the Operational exposures section — and still validates.');
  } else {
    note('ok', `line ${c.line}: buildInput() passes the fourth argument.`);
  }
}
if (usesQeaInput && !buildInputCalls.length) {
  note('warn', 'qea-input is required but buildInput() was not found — check for an alias.');
}

/* ── The report route ────────────────────────────────────────────────────── */
const routeRe = /app\.(post|use)\s*\(\s*['"]\/api\/report['"]\s*,/;
const routeLine = lines.findIndex((l) => routeRe.test(l));
if (routeLine === -1) {
  note('warn', "No app.post('/api/report', …) found. If your route is mounted on a Router, " +
               'apply the two lines below by hand.');
} else {
  note('info', `/api/report route at line ${routeLine + 1}`);
}

/* ── The network-scan route, for attachDNEL ──────────────────────────────── */
const netLine = lines.findIndex((l) => /app\.(post|use)\s*\(\s*['"]\/api\/network-scan['"]\s*,/.test(l));
note(netLine === -1 ? 'warn' : 'info',
  netLine === -1 ? 'No /api/network-scan route found — attachDNEL cannot be placed automatically.'
                 : `/api/network-scan route at line ${netLine + 1}`);
if (netLine !== -1 && !usesRoute && !usesDnel) {
  note('warn', 'DNEL is not attached to the network scan response. The report does not need ' +
               'this (buildInput computes DNEL from raw networkData), but the UI and the CBOM ' +
               'will fall back to the client-side scorer rather than the server figure.');
}

/* ── Propose the edit ────────────────────────────────────────────────────── */
let out = src;

if (!usesRoute) {
  /* Insert the require after the last top-level require in the first 80 lines. */
  let lastReq = -1;
  for (let i = 0; i < Math.min(lines.length, 80); i++) {
    if (/^\s*(const|let|var)\s+.*=\s*require\(/.test(lines[i])) lastReq = i;
  }
  if (lastReq === -1) {
    note('error', 'Could not find a require block to insert into. Add by hand:\n' +
                  "    const qeaRoute = require('./qea-route');");
  } else {
    const insert = "const qeaRoute = require('./qea-route');";
    const arr = out.split('\n');
    arr.splice(lastReq + 1, 0, insert);
    out = arr.join('\n');
    actions.push(`insert  line ${lastReq + 2}:  ${insert}`);
  }
}

if (routeLine !== -1) {
  note('action',
    'Replace your /api/report handler with the drop-in one. It owns the 409 gate, the\n' +
    '        filename, validation and the error shapes, so there is nothing to get subtly wrong:\n\n' +
    "            app.post('/api/report', qeaRoute.handler({ reportProfile }));\n\n" +
    '        This script does NOT rewrite the handler body automatically — your route may carry\n' +
    '        auth, rate limiting or tenancy that I cannot see, and silently discarding those\n' +
    '        would be a far worse bug than the one being fixed.');
}

if (netLine !== -1) {
  note('action',
    'In /api/network-scan, immediately before you respond:\n\n' +
    '            qeaRoute.attachDNEL(result, req.body.hosts);\n\n' +
    '        It attaches result.dnel and folds the DNEL findings into the severity counts.');
}

/* ── Report ──────────────────────────────────────────────────────────────── */
const ICON = { ok: '  ok  ', info: ' info ', warn: ' warn ', error: ' FAIL ', action: ' TODO ' };
console.log(`\nInspecting ${path.basename(FILE)} (${lines.length} lines)\n` + '─'.repeat(78));
for (const [level, msg] of findings) console.log(`${ICON[level]} ${msg}`);
console.log('─'.repeat(78));

if (actions.length) {
  console.log('\nAutomatic edits available:');
  actions.forEach((a) => console.log('   ' + a));
}

const manual = findings.filter(([l]) => l === 'action').length;
if (manual) console.log(`\n${manual} edit${manual === 1 ? '' : 's'} must be made by hand — see TODO above.`);

if (!WRITE) {
  console.log('\nNothing was changed. Re-run with --write to apply the automatic edits.\n');
  process.exit(findings.some(([l]) => l === 'error') ? 1 : 0);
}

if (!actions.length) {
  console.log('\nNo automatic edits to make.\n');
  process.exit(0);
}

const backup = FILE + '.bak-' + new Date().toISOString().replace(/[:.]/g, '-');
fs.writeFileSync(backup, src);

/* Never leave a syntactically broken server behind. */
/* Must keep a .js extension — node --check infers the module type from it. */
const tmp = FILE.replace(/\.js$/, '') + '.patch-check.js';
fs.writeFileSync(tmp, out);
try {
  require('child_process').execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' });
} catch (e) {
  fs.unlinkSync(tmp);
  console.error('\nThe patched file does not parse. Nothing was changed.');
  console.error(String(e.stderr || e.message).slice(0, 500) + '\n');
  process.exit(1);
}
fs.unlinkSync(tmp);
fs.writeFileSync(FILE, out);

console.log(`\nBackup: ${path.basename(backup)}`);
console.log(`Patched: ${path.basename(FILE)} — parses cleanly.`);
console.log('Now make the TODO edits above, then run: npm run preflight\n');
