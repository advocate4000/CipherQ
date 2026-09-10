# CipherQ — QEA + DNEL deployment package

Everything needed to get the DNEL work into the platform, except `server.js`,
which has never been uploaded and is the one file that decides whether the
report changes at all.

**Read §1 before anything else.** Deploying the frontend alone will not change
the `.docx`.

---

## 1. What deploying what actually gets you

| Want | Deploy | Server edit? |
|---|---|---|
| DNEL tab, three-axis strip | `index.html` | no |
| CycloneDX CBOM with DNEL, schema-valid | `index.html` | no |
| **QEA `.docx` with DNEL** | the modules below | **yes** |

`index.html` is the browser. The `.docx` is built server-side and returned from
`POST /api/report` — nothing in `index.html` is in that path.

---

## 2. Install

```bash
npm install          # regenerates nothing; the lock in this package is correct
npm run preflight    # 16 checks — must pass before you deploy
```

`package-lock.json` here is regenerated and **`npm ci` passes**. The version you
had pinned `docx` at 8.5.0 while the manifest asked for `^9.7.1`, which is a hard
`npm ci` failure — if your deploy runs `npm ci`, it would not have built at all.

`ajv`, `ajv-formats` and `@cyclonedx/cyclonedx-library` are now **devDependencies**
— they are for `validate-cbom.js` and have no business in a production install.

---

## 3. Files

### New

| File | What it is |
|---|---|
| `dnel.js` | The DNEL model — surface classification, per-host scoring, findings. Single source of truth; `qea-input.js` and `cbom.js` both read it. |
| `qea-route.js` | **Drop-in `/api/report` handler.** Owns the 409 profile gate, validation, filename and error shapes, so wiring is two lines rather than a hand-edited handler. |
| `preflight.js` | 16 checks proving the whole chain works before you deploy. |
| `validate-cbom.js` | Validates an exported CBOM against the official CycloneDX 1.6 schema. |
| `apply-server-patch.js` | Inspects your `server.js`, tells you what is wired, makes the safe edit. |
| `sample-cbom.cdx.json` | A known-good export, for diffing against yours. |

### Changed

| File | Change |
|---|---|
| `qea-input.js` | Takes `networkData`; emits Class D, the operator-access track, and now `qei_max` / `complete` |
| `qea-doc.js` | Renders Class D and *Operational exposures*; **renders the real denominator** instead of a hardcoded `/ 100`; glossary corrected to seven dimensions |
| `qei.js` | METHOD_VERSION 3 — seventh dimension, *Operational access*, max 15 |
| `report-profile.js` | `rate_card.access_low` / `access_high`, required only where a Class D exposure was raised |
| `cbom.js` | Passes `networkData` into `deriveFacts` — it was accepted and ignored |
| `index.html` | Three-axis strip, DNEL tab, host-table column, **DNEL in the CycloneDX export**, four schema-conformance fixes |
| `package.json` | `docx ^9.7.1`; test tooling moved to devDependencies; new scripts |
| `package-lock.json` | Regenerated — `npm ci` passes |

### Not in this package — still needed from you

`server.js`, `scanner.js`, `ssrf-guard.js`, `vendor.js`. Only `server.js` blocks.

---

## 4. Wire it up

```bash
node apply-server-patch.js            # inspect, change nothing
node apply-server-patch.js --write    # apply, after a backup
```

It reports which generator is currently wired, checks the `buildInput` arity, and
inserts the require. It does **not** rewrite your route handler automatically —
your route may carry auth, rate limiting or tenancy I cannot see, and silently
discarding those would be a worse bug than the one being fixed. It prints the two
edits to make by hand:

**`POST /api/report`** — replace the handler body with:

```js
app.post('/api/report', qeaRoute.handler({ reportProfile }));
```

Keep any middleware you already have on the route. If your profiles are
tenant-scoped, pass your own loader:

```js
app.post('/api/report', qeaRoute.handler({
  reportProfile,
  loadProfile: (domain, req) => reportProfile.read(domain, req.tenantId),
}));
```

**`POST /api/network-scan`** — immediately before you respond:

```js
qeaRoute.attachDNEL(result, req.body.hosts);
```

The report does *not* need this — `buildInput` computes DNEL from raw
`networkData`. It is so the UI and the CBOM read the server's figure rather than
the client's fallback, keeping one scorer behind one concept.

---

## 5. Order

1. `npm install` — the lock fix first; nothing else matters if the build fails
2. `npm run preflight` — must be 16/16
3. Deploy the modules: `dnel.js`, `qei.js`, `qea-input.js`, `qea-doc.js`,
   `report-profile.js`, `qea-route.js`, `cbom.js`
4. Patch `server.js` (§4)
5. Deploy `index.html`
6. `npm run preflight` once more on the target, then restart

---

## 6. Confirming it worked

Open the produced `.docx` and read the section headings.

| Old — `report.js` | New — `qea-doc.js` |
|---|---|
| Executive Summary | Board summary |
| Findings | Your exposure window |
| Vendor Security Scorecard | What we verified |
| CBOM Board Metrics | Exposures by threat model |
| | Retrospective / Forward / Present-day / **Operational** exposures |
| | Sequence of work · What changes if you act |
| | Regulatory position · Method · Terms · Observation log |

- **14 sections including *Operational exposures*** — it worked.
- **13 sections** — `networkData` is not reaching `buildInput`.
- **"Executive Summary"** — `server.js` is still calling the old generator.

The response also carries `X-CipherQ-QEI`, `X-CipherQ-QEI-Max` and
`X-CipherQ-Sections`, so you can check without opening the file:

```bash
curl -sI -X POST https://…/api/report -d @payload.json | grep X-CipherQ
```

For the CBOM, export one from the UI and:

```bash
node validate-cbom.js ~/Downloads/CipherQ_CBOM_yourdomain_2026-09-10.cdx.json
```

It should report schema PASS, no dangling refs, and `threat axes HNDL, TNFL, DNEL`.
If `DNEL source` says `client` rather than `server`, the `attachDNEL` edit in §4
has not been made.

---

## 7. Two things that will surprise you on first run

**Every existing score moves.** METHOD_VERSION 2 → 3 rebalanced all seven
dimensions to make room for *Operational access*. `getBoardMetrics` suppresses the
trend across the version boundary rather than presenting the shift as progress —
expect one suppressed trend per domain. That is correct, not a bug.

**A 409 on the first report is normal.** The QEA path gates on a report profile:
retention years and their basis, authorisation reference, rate card, board
narrative. These are judgements a scan cannot make. The 409 names each missing
field and why. Set them via `PUT /api/report/profile/<domain>` and request again.
The two new access-rate fields are required **only** where the scan actually found
a reachable operator surface, so existing profiles for estates with none stay
valid.

---

## 8. What the preflight actually checks

Every one of these is something that has broken at least once:

- all six modules load and export what their callers import
- `docx` is installed at ≥ 9, and the manifest and lock agree (`npm ci` viability)
- `METHOD_VERSION` is 3, seven dimensions, maxima total 100
- DNEL scores an estate with a network scan, and reports `assessed: false` with
  named evidence gaps without one
- the denominator is **85** without a network scan and **100** with — the bug that
  had reports printing `55 / 100` when the honest figure was `55 / 85`
- a real `.docx` builds, validates, reconciles, has zero outstanding TODOs and
  contains *Operational exposures*
- the document contains no literal `undefined`, `[object Object]` or `NaN`
- the no-network document degrades honestly — 13 sections, scored out of 85
- the route returns 409 on an empty profile, and names the access rate card when
  operator surfaces were found
- the route returns a 200 with a 14-section buffer on a complete profile

---

## 9. Still outstanding

- **`server.js` has never been uploaded.** Send it and I will make the §4 edits
  rather than describe them.
- `scanner.js`, `ssrf-guard.js`, `vendor.js` likewise absent — they are named in
  the lint script, so `npm run lint` will fail until the full tree is present.
  `npm run preflight` does not depend on them.
