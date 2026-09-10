'use strict';
/* Validate an exported CBOM against the official CycloneDX 1.6 JSON schema.
 *
 *   node validate-cbom.js path/to/CipherQ_CBOM_example.com_2026-09-10.cdx.json
 *   node validate-cbom.js                     # defaults to sample-cbom.cdx.json
 *
 * Worth having in CI. The `relatedCryptoMaterial` / `related-crypto-material`
 * enum error this catches was in the export from the day it was written and
 * made every document invalid, silently — a consumer would simply have
 * rejected the file.
 *
 * Beyond the schema it also checks referential integrity, which the schema
 * cannot: every vulnerabilities[].affects[].ref must name a bom-ref that is
 * actually declared in this document.
 */

const fs = require('fs');
const path = require('path');

const file = process.argv[2] || path.join(__dirname, 'sample-cbom.cdx.json');
if (!fs.existsSync(file)) {
  console.error(`\nNot found: ${file}`);
  console.error('Export a CBOM from the platform and pass its path.\n');
  process.exit(2);
}

let Ajv, addFormats;
try {
  Ajv = require('ajv');
  addFormats = require('ajv-formats');
} catch {
  console.error('\nMissing dev dependencies. Run:  npm install\n');
  process.exit(2);
}

const SCHEMA_DIR = path.join(
  __dirname, 'node_modules', '@cyclonedx', 'cyclonedx-library', 'res', 'schema'
);
if (!fs.existsSync(SCHEMA_DIR)) {
  console.error('\nCycloneDX schemas not found. Run:  npm install\n');
  process.exit(2);
}

const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
addFormats(ajv);

/* The 1.6 schema $refs its siblings by bare filename, so register both the
   filename form and whatever $id each declares. */
for (const f of fs.readdirSync(SCHEMA_DIR)) {
  if (!f.endsWith('.json') || f.startsWith('bom-')) continue;
  try {
    const s = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, f), 'utf8'));
    ajv.addSchema(s, 'http://cyclonedx.org/schema/' + f);
    if (s.$id && s.$id !== 'http://cyclonedx.org/schema/' + f) ajv.addSchema(s, s.$id);
  } catch { /* not a JSON schema */ }
}

const schemaFile = fs.readdirSync(SCHEMA_DIR).find((f) => /^bom-1\.6.*\.schema\.json$/.test(f));
const validate = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, schemaFile), 'utf8')));

const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
const ok = validate(doc);

console.log(`\nValidating ${path.basename(file)} against ${schemaFile}\n` + '─'.repeat(72));

if (!ok) {
  console.log(' FAIL  CycloneDX 1.6 schema');
  validate.errors.slice(0, 25).forEach((e) =>
    console.log(`        ${e.instancePath || '(root)'} ${e.message} ` +
                (e.params ? JSON.stringify(e.params).slice(0, 110) : '')));
  if (validate.errors.length > 25) console.log(`        …and ${validate.errors.length - 25} more`);
} else {
  console.log('  ok   CycloneDX 1.6 schema');
}

/* ── Referential integrity — beyond what the schema checks ──────────────── */
const declared = new Set((doc.components || []).map((c) => c['bom-ref']).filter(Boolean));
const dangling = [];
for (const v of doc.vulnerabilities || []) {
  for (const a of v.affects || []) {
    if (!declared.has(a.ref)) dangling.push(`${v.id} → ${a.ref}`);
  }
}
if (dangling.length) {
  console.log(` FAIL  ${dangling.length} affects[] reference an undeclared bom-ref`);
  dangling.slice(0, 10).forEach((d) => console.log('        ' + d));
} else {
  console.log(`  ok   referential integrity — ${declared.size} bom-refs, no dangling affects`);
}

/* ── Coverage: does this document carry all three axes? ─────────────────── */
const props = Object.fromEntries(
  ((doc.metadata && doc.metadata.component && doc.metadata.component.properties) || [])
    .map((p) => [p.name, p.value])
);
const dnelComps = (doc.components || []).filter((c) => String(c['bom-ref']).startsWith('dnel:')).length;
const axes = props['cipherq:threatAxes'] || '(not stated)';
console.log('─'.repeat(72));
console.log(`  components        ${(doc.components || []).length}  ` +
            `(${dnelComps} operator-surface)`);
console.log(`  vulnerabilities   ${(doc.vulnerabilities || []).length}`);
console.log(`  threat axes       ${axes}`);
if (props['cipherq:dnelIndex']) {
  console.log(`  DNEL              index ${props['cipherq:dnelIndex']} ${props['cipherq:dnelBand'] || ''}` +
              `, ${props['cipherq:dnelSurfaceHosts']}/${props['cipherq:dnelHostsConsidered']} hosts` +
              `, source ${props['cipherq:dnelSource']}`);
} else {
  console.log('  DNEL              absent — the network scan did not run, or the export predates DNEL');
}
console.log('');

process.exit(ok && !dangling.length ? 0 : 1);
