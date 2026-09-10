'use strict';
/* Set a report profile from a JSON file, without hand-writing curl.
 *
 *   node set-profile.js <domain> [file] [--url https://your-host]
 *
 *   node set-profile.js cipherq.co                       # shows what is missing
 *   node set-profile.js cipherq.co profile-template.json # sends it
 *
 * Defaults to http://localhost:3000, or CIPHERQ_URL if set.
 *
 * Keys beginning with "_" are stripped — the template uses them for notes.
 * Values beginning with "TODO" are sent as-is on purpose: report-profile.js
 * treats them as unset, so the gate keeps naming them and a placeholder can
 * never reach a delivered report as though it were an answer.
 */

const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const urlIdx = args.indexOf('--url');
const BASE = (urlIdx !== -1 ? args.splice(urlIdx, 2)[1] : null) ||
             process.env.CIPHERQ_URL || 'http://localhost:3000';

const domain = args[0];
const file = args[1];

if (!domain) {
  console.error('\nUsage: node set-profile.js <domain> [file.json] [--url https://host]\n');
  process.exit(2);
}

/** Drop the template's underscore-prefixed notes, recursively. */
function strip(v) {
  if (Array.isArray(v)) return v.map(strip);
  if (v && typeof v === 'object') {
    const out = {};
    for (const [k, val] of Object.entries(v)) {
      if (k.startsWith('_')) continue;
      out[k] = strip(val);
    }
    return out;
  }
  return v;
}

function show(res, body) {
  const missing = body.missing || [];
  console.log(`\n${body.domain || domain} — ${missing.length === 0 ? 'COMPLETE' : missing.length + ' field(s) outstanding'}`);
  if (missing.length) {
    console.log('─'.repeat(72));
    for (const m of missing) console.log(`  ${m.field}\n      ${m.why}`);
    console.log('─'.repeat(72));
    console.log('\nEdit your profile JSON and run this again. A value starting with');
    console.log('"TODO" counts as unset — that is why it still appears above.\n');
  } else {
    console.log('\nProfile complete. Request the report; it will build.\n');
  }
}

(async () => {
  const target = `${BASE.replace(/\/$/, '')}/api/report/profile/${encodeURIComponent(domain)}`;

  try {
    if (!file) {
      const r = await fetch(target);
      if (!r.ok) {
        console.error(`\nGET ${target} → ${r.status}`);
        if (r.status === 404) {
          console.error('The profile route is missing. This server predates the QEA wiring —');
          console.error('deploy the patched server.js.\n');
        }
        process.exit(1);
      }
      return show(r, await r.json());
    }

    const p = path.resolve(file);
    if (!fs.existsSync(p)) {
      console.error(`\nNot found: ${p}\n`);
      process.exit(2);
    }

    let patch;
    try {
      patch = strip(JSON.parse(fs.readFileSync(p, 'utf8')));
    } catch (e) {
      console.error(`\n${path.basename(p)} is not valid JSON: ${e.message}\n`);
      process.exit(2);
    }

    const r = await fetch(target, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
    const body = await r.json().catch(() => ({}));

    if (!r.ok) {
      console.error(`\nPUT ${target} → ${r.status}`);
      console.error(body.error || '(no message)');
      console.error('');
      process.exit(1);
    }

    console.log(`\nSent ${Object.keys(patch).length} top-level field(s) to ${domain}.`);
    show(r, body);
  } catch (e) {
    console.error(`\nCould not reach ${BASE} — ${e.message}`);
    console.error('Pass --url, or set CIPHERQ_URL.\n');
    process.exit(1);
  }
})();
