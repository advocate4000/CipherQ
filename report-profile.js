'use strict';
/* ═══════════════════════════════════════════════════════════════════════
   Report profile — the half of a QEA that a scan cannot observe

   A scan establishes what an estate does. It cannot establish how long the
   client must keep the data confidential, what authority the engagement was
   run under, what the work costs at your rates, or what the board is being
   asked to approve. Those are judgements, and the report is worthless — or
   worse, wrong — without them.

   They are stored per tenant and domain, alongside the CBOM store and under
   the same tenant namespacing, so one client's retention figure can never be
   read into another client's report.

   Retention deserves particular care. It is worth 20 of the 100 index points
   and it is the entire basis of the exposure window. Get it in writing.
   ═══════════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const path = require('path');
const os = require('os');

const DATA_DIR = process.env.CBOM_DATA_DIR || path.join(os.tmpdir(), 'cipherq-cbom');
const DEFAULT_TENANT = 'default';

const safeSegment = s => String(s).replace(/[^a-zA-Z0-9.\-]/g, '_').toLowerCase();

function profileDir(tenantId) {
  const dir = path.join(DATA_DIR, safeSegment(tenantId || DEFAULT_TENANT), 'report-profiles');
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  return dir;
}
const profilePath = (domain, tenantId) =>
  path.join(profileDir(tenantId), safeSegment(domain) + '.json');

/* What must be present before a report can be issued. Each entry names the
   field and says why the scan cannot supply it, because that message is what
   the caller sees when the build is refused. */
const REQUIRED = [
  ['name', 'Client legal entity name'],
  ['sector', 'Sector, e.g. Legal & Professional Services'],
  ['data_retention_years', 'Years the client must keep this data confidential. Worth 20 index points and the basis of the exposure window — client-attested, get it in writing'],
  ['retention_basis', 'The obligation behind that period, e.g. "Client matter files retained 15 years under SRA requirements"'],
  ['regulations', 'Applicable regimes, e.g. FCA, GDPR, SOC 2'],
  ['authorisation', 'Written authorisation reference. Active probing without recorded authority is an offence under the Computer Misuse Act 1990, which has no research defence'],
  ['residual_explanation', 'Why the index does not reach zero for this client'],
  ['owners.security', 'Team owning the key-establishment track'],
  ['owners.operations', 'Team owning the hygiene track'],
  ['rate_card.kex_low', 'Key establishment, lower bound — your rate card'],
  ['rate_card.kex_high', 'Key establishment, upper bound'],
  ['rate_card.hygiene_low', 'Hygiene work, lower bound'],
  ['rate_card.hygiene_high', 'Hygiene work, upper bound'],
  /* Only required when the scan actually found a reachable operator surface —
     see missing(). An estate with none does not get a cost line for work it
     does not need, and is not blocked from reporting by a rate it will never
     print. */
  ['rate_card.access_low', 'Operator-access work, lower bound — gateway placement, management-plane key exchange, credential rotation'],
  ['rate_card.access_high', 'Operator-access work, upper bound'],
  ['board.position_good', 'What is competent about this estate'],
  ['board.position_bad', 'The gap, framed against the client\'s own obligation'],
  ['board.exposure_statement', 'The retrospective consequence in the client\'s terms'],
  ['board.ask_headline', 'The figure and the timeframe — must match the investment total'],
  ['board.ask_detail', 'The two tracks and who owns each'],
  ['board.outcome', 'Modelled index after the work'],
  ['board.if_deferred', 'What a month of delay costs'],
  ['board.decision', 'The decision being put to the board'],
  ['board.decision_owner', 'Recommended accountable owner'],
];

const dig = (o, dotted) => dotted.split('.').reduce((n, k) => (n == null ? n : n[k]), o);

const isSet = v => {
  if (v === undefined || v === null || v === '') return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'string') return !v.startsWith('TODO');
  return true;
};

function read(domain, tenantId = DEFAULT_TENANT) {
  try { return JSON.parse(fs.readFileSync(profilePath(domain, tenantId), 'utf8')); }
  catch { return {}; }
}

/* Merged, not replaced — a caller updating the rate card should not have to
   resend the board narrative, and a PUT that silently blanked the retention
   figure would be the worst possible failure mode here. */
function write(domain, patch, tenantId = DEFAULT_TENANT) {
  const current = read(domain, tenantId);
  const merged = { ...current };
  for (const [k, v] of Object.entries(patch || {})) {
    merged[k] = (v && typeof v === 'object' && !Array.isArray(v))
      ? { ...(current[k] || {}), ...v }
      : v;
  }
  merged._updated = new Date().toISOString();

  const p = profilePath(domain, tenantId);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(merged, null, 2), 'utf8');
  fs.renameSync(tmp, p);
  return merged;
}

/* `opts.accessTrack` says whether this scan raised a Class D exposure. When
   it did not, the operator-access rates are not required: the report has no
   band to cost, and demanding a rate for absent work would block a build for
   no reason. Callers that cannot tell should omit it and get the strict set. */
function missing(profile, opts = {}) {
  const needAccess = opts.accessTrack !== false;
  return REQUIRED
    .filter(([f]) => (needAccess || !f.startsWith('rate_card.access_')))
    .filter(([f]) => !isSet(dig(profile, f)))
    .map(([field, why]) => ({ field, why }));
}

const isComplete = (profile, opts = {}) => missing(profile, opts).length === 0;

/* Retention drives the data-lifetime dimension of the index. Returns null
   when unset so the scorer marks that dimension unassessed rather than
   scoring it zero — an unknown retention is not a short one. */
function retentionYears(domain, tenantId = DEFAULT_TENANT) {
  const v = read(domain, tenantId).data_retention_years;
  return typeof v === 'number' && isFinite(v) ? v : null;
}

module.exports = { read, write, missing, isComplete, retentionYears, REQUIRED, profilePath };
