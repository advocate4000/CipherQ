'use strict';
/* Preflight — run before deploying. Proves the QEA chain works on this box,
 * end to end, without needing the server running.
 *
 *   node preflight.js
 *
 * Exits non-zero on the first failure, so it drops straight into CI.
 * Every check is a thing that has actually broken at least once.
 */

const fs = require('fs');
const path = require('path');

let failed = 0;
const results = [];

function check(name, fn) {
  try {
    const detail = fn();
    results.push(['PASS', name, detail || '']);
  } catch (e) {
    failed++;
    results.push(['FAIL', name, e.message]);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

/* ── 1. Every module in the QEA chain exists and loads ──────────────────── */
const REQUIRED = [
  ['./qei', ['computeQEI', 'reconcile', 'operationalAccessPoints', 'METHOD_VERSION', 'MAX']],
  ['./dnel', ['assessDNEL', 'SURFACES', 'BANDS']],
  ['./qea-input', ['buildInput', 'deriveFacts', 'project']],
  ['./qea-doc', ['build', 'validate']],
  ['./report-profile', ['read', 'write', 'missing', 'isComplete']],
  ['./qea-route', ['handler', 'attachDNEL']],
];

for (const [mod, exports_] of REQUIRED) {
  check(`module ${mod}`, () => {
    assert(fs.existsSync(path.join(__dirname, mod.slice(2) + '.js')), 'file not deployed');
    const m = require(mod);
    const missing = exports_.filter((k) => !(k in m));
    assert(!missing.length, 'missing exports: ' + missing.join(', '));
    return exports_.length + ' exports';
  });
}

/* ── 2. docx is installed, and at the version the renderer was built against */
check('dependency docx >= 9', () => {
  const docx = require('docx');
  assert(docx && docx.Document, 'docx did not load');
  const lock = JSON.parse(fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'));
  const v = lock.packages && lock.packages['node_modules/docx'] && lock.packages['node_modules/docx'].version;
  assert(v, 'docx not in package-lock.json');
  assert(parseInt(v, 10) >= 9, `lock pins docx ${v}; the renderer needs >= 9`);
  return 'v' + v;
});

/* ── 3. The manifest and the lock agree — npm ci is a hard failure otherwise */
check('package.json and lock agree', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'));
  const rootDeps = (lock.packages && lock.packages[''] && lock.packages[''].dependencies) || {};
  const drift = Object.entries(pkg.dependencies || {})
    .filter(([k, want]) => rootDeps[k] !== want)
    .map(([k, want]) => `${k}: manifest ${want}, lock ${rootDeps[k] || 'absent'}`);
  assert(!drift.length, drift.join(' | ') + ' — npm ci will fail');
  return Object.keys(pkg.dependencies || {}).length + ' runtime deps';
});

/* ── 4. The index is on method version 3 and the maxima still total 100 ─── */
check('QEI method version and maxima', () => {
  const { METHOD_VERSION, MAX } = require('./qei');
  assert(METHOD_VERSION === 3, `METHOD_VERSION is ${METHOD_VERSION}, expected 3`);
  const total = Object.values(MAX).reduce((a, b) => a + b, 0);
  assert(total === 100, `dimension maxima total ${total}, expected 100`);
  assert(Object.keys(MAX).length === 7, `${Object.keys(MAX).length} dimensions, expected 7`);
  return 'v3, 7 dimensions, 100 points';
});

/* ── 5. DNEL scores the worked estate, and drops out cleanly without a scan */
check('DNEL assessed and unassessed paths', () => {
  const { assessDNEL } = require('./dnel');
  const { scan, networkData } = require('./test-dnel.js');
  const withNet = assessDNEL(scan, networkData);
  const without = assessDNEL(scan, null);
  assert(withNet.assessed, 'DNEL did not assess with a network scan present');
  assert(withNet.points > 0, 'DNEL scored zero points on an estate with OT and telnet');
  assert(!without.assessed, 'DNEL claimed to be assessed with no network scan');
  assert(without.points === 0, 'unassessed DNEL contributed points');
  assert(without.gaps.length > 0, 'unassessed DNEL named no evidence gaps');
  return `assessed ${withNet.index} ${withNet.band.label}, ${withNet.points}/${withNet.max} pts`;
});

/* ── 6. The denominator is carried, not assumed ─────────────────────────── */
check('index drops unassessed dimensions from the denominator', () => {
  const { buildInput } = require('./qea-input');
  const { scan, httpData, profile, networkData } = require('./test-dnel.js');
  const a = buildInput(scan, httpData, profile, networkData).assessment;
  const b = buildInput(scan, httpData, profile, null).assessment;
  assert(a.qei_max === 100, `full scan max is ${a.qei_max}, expected 100`);
  assert(b.qei_max === 85, `no-network max is ${b.qei_max}, expected 85`);
  assert(a.complete === true && b.complete === false, 'complete flag wrong');
  return `${a.qei}/${a.qei_max} with scan · ${b.qei}/${b.qei_max} without`;
});

/* ── 7. A real document builds, validates and reconciles ────────────────── */
let builtBuffer = null;
const asyncChecks = [
  async function documentBuilds() {
    const { buildInput } = require('./qea-input');
    const { build, validate } = require('./qea-doc');
    const { scan, httpData, profile, networkData } = require('./test-dnel.js');
    const input = buildInput(scan, httpData, profile, networkData);

    const v = validate(input);
    assert(v.ok, 'validate() returned not-ok');
    assert(v.reconciles, 'index does not reconcile against its components');
    assert(v.todos.length === 0, `${v.todos.length} outstanding TODOs`);

    const { buffer, sections } = await build(input);
    builtBuffer = buffer;
    assert(buffer && buffer.length > 10000, 'document is implausibly small');

    const titles = sections.map((s) => s.title);
    assert(
      titles.includes('Operational exposures'),
      'no "Operational exposures" section — DNEL did not reach the document'
    );
    assert(titles.length === 14, `${titles.length} sections, expected 14`);
    return `${titles.length} sections, ${buffer.length.toLocaleString()} bytes`;
  },

  /* ── 8. Nothing rendered as a placeholder ───────────────────────────── */
  async function documentIsClean() {
    assert(builtBuffer, 'no document to inspect');
    const AdmZip = require('adm-zip');
    const xml = new AdmZip(builtBuffer).readAsText('word/document.xml');
    const text = xml.replace(/<[^>]+>/g, ' ');
    for (const bad of ['undefined', '[object Object]', 'NaN']) {
      assert(!text.includes(bad), `the document contains the literal "${bad}"`);
    }
    /* The denominator must be the real one, not a hardcoded 100. */
    assert(text.includes('/ 100'), 'full-scan document does not show its denominator');
    return 'no undefined / [object Object] / NaN';
  },

  /* ── 9. The no-network document degrades honestly ───────────────────── */
  async function noNetworkDocumentIsHonest() {
    const { buildInput } = require('./qea-input');
    const { build } = require('./qea-doc');
    const { scan, httpData, profile } = require('./test-dnel.js');
    const { buffer, sections } = await build(buildInput(scan, httpData, profile, null));
    const AdmZip = require('adm-zip');
    const text = new AdmZip(buffer).readAsText('word/document.xml').replace(/<[^>]+>/g, ' ');
    assert(
      !sections.map((s) => s.title).includes('Operational exposures'),
      'no-network document claims an Operational exposures section'
    );
    assert(
      text.includes('/ 85'),
      'no-network document prints the wrong denominator — it must be 85, not 100'
    );
    return `${sections.length} sections, scored out of 85`;
  },

  /* ── 10. The route module wires up and gates as documented ──────────── */
  async function routeGatesOnProfile() {
    const qeaRoute = require('./qea-route');
    const { scan, httpData, networkData } = require('./test-dnel.js');
    const h = qeaRoute.handler({ loadProfile: () => ({}) });   // deliberately empty profile

    let status = null, payload = null;
    const res = {
      status(s) { status = s; return this; },
      json(p) { payload = p; return this; },
      setHeader() {}, send() {},
    };
    await h({ body: { scanResult: scan, httpData, networkData } }, res);
    assert(status === 409, `empty profile returned ${status}, expected 409`);
    assert(Array.isArray(payload.missing) && payload.missing.length, '409 named no missing fields');
    const fields = payload.missing.map((m) => m.field);
    assert(
      fields.some((f) => String(f).includes('access_')),
      'an estate with operator surfaces was not asked for the access rate card'
    );
    return `409 with ${payload.missing.length} named fields`;
  },

  async function routeBuildsWithFullProfile() {
    const qeaRoute = require('./qea-route');
    const { scan, httpData, networkData, profile } = require('./test-dnel.js');
    const h = qeaRoute.handler({ loadProfile: () => profile });

    let status = 200, headers = {}, sent = null;
    const res = {
      status(s) { status = s; return this; },
      json(p) { sent = p; return this; },
      setHeader(k, v) { headers[k] = v; },
      send(b) { sent = b; return this; },
    };
    await h({ body: { scanResult: scan, httpData, networkData } }, res);
    assert(status === 200, `complete profile returned ${status}: ${JSON.stringify(sent).slice(0, 200)}`);
    assert(Buffer.isBuffer(sent), 'handler did not send a buffer');
    assert(/\.docx"$/.test(headers['Content-Disposition'] || ''), 'no .docx filename set');
    assert(headers['X-CipherQ-Sections'] === '14', `sections header says ${headers['X-CipherQ-Sections']}`);
    return `200, ${sent.length.toLocaleString()} bytes, ${headers['X-CipherQ-QEI']}/${headers['X-CipherQ-QEI-Max']}`;
  },
];

(async () => {
  for (const fn of asyncChecks) {
    try {
      const detail = await fn();
      results.push(['PASS', fn.name, detail || '']);
    } catch (e) {
      failed++;
      results.push(['FAIL', fn.name, e.message]);
    }
  }

  const w = Math.max(...results.map((r) => r[1].length));
  console.log('\nCipherQ QEA preflight\n' + '─'.repeat(w + 46));
  for (const [state, name, detail] of results) {
    const mark = state === 'PASS' ? '  ok  ' : ' FAIL ';
    console.log(`${mark} ${name.padEnd(w)}  ${detail}`);
  }
  console.log('─'.repeat(w + 46));

  if (failed) {
    console.log(`${failed} check${failed === 1 ? '' : 's'} failed — do not deploy.\n`);
    process.exit(1);
  }
  console.log('All checks passed. The QEA chain is sound on this box.');
  console.log('If the deployed report still looks old, the cause is in server.js.\n');
})();
