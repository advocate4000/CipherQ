# DNEL merged into the platform

Third quantum risk axis, wired through the scanner, the index, the dashboard
and the QEA report.

|  | HNDL | TNFL | **DNEL** |
|---|---|---|---|
| Property | Confidentiality | Authenticity | **Access & non-repudiation** |
| The move | Records traffic, decrypts it later | Recovers a signing key, **mints new** trusted artifacts | Presents **genuine** credentials and authenticates |
| Detectable? | No — the capture is passive | Yes — a forged artifact exists to examine | **No — nothing is anomalous** |
| Retired by | Nothing. Captured traffic stays captured | Re-issue under PQ signatures | **Rotation** |

That last row is the distinction worth defending. Class A and Class D both get
worse with delay, but a credential recovered from a five-year-old handshake is
worthless if the key it authenticates has since been re-issued. Traffic
captured five years ago is not. It is why the operator-access track is scoped
around rotation and gateway placement rather than around cryptography alone.

---

## What did not upload

`server.js`, `scanner.js`, `ssrf-guard.js` and `vendor.js` were named in the
manifest but no file arrived — 16 of the 20. Everything below is complete and
tested **except** the `server.js` wiring in §3, which is written as a patch
against the documented interface rather than applied, because I could not read
the file.

## 1. New file

**`dnel.js`** — owns the threat model, the port classification, the per-host
scoring and the findings. It is the single source of truth: the UI reads the
block off the network scan response rather than recomputing, and `cbom.js` and
`qea-input.js` read the same one. The platform has been bitten once by two
independent scorers for one concept; this axis does not repeat it.

Two weight scales, named apart because they answer different questions —
`weight` (0–10) feeds the QEI dimension, `hostWeight` (0–46) feeds the per-host
figure in the UI. Conflating them had the server and the UI fallback disagreeing
by a point before I separated them.

## 2. Changed files

| File | Change |
|---|---|
| `qei.js` | **METHOD_VERSION 2 → 3.** Seventh dimension, *Operational access*, max 15. Unassessed without a network scan, so it drops from the denominator like data lifetime |
| `qea-input.js` | Takes `networkData`; emits **Class D** exposures, an operator-access sequence track, a third investment band, two verification measures, an assurance row. Reads components **by name** |
| `qea-doc.js` | Renders Class D throughout. Projection gains a fourth stage. Two rendering bugs fixed — see §5 |
| `cbom.js` | Passes `networkData` into `deriveFacts` — it was accepted and ignored |
| `report-profile.js` | `rate_card.access_low/high`, required **only** when the scan found a reachable operator surface |
| `index.html` | Three-axis strip, DNEL tab, host-table column. Merged onto your newer frontend |
| `package.json` | `dnel.js` added to the lint script |

### The rebalance

Fifteen points had to come from somewhere. They came from dimensions that
either overlap with the new one or are explicitly not quantum exposures. The
two carrying the report's central argument are untouched:

| Dimension | v2 | v3 | Why |
|---|---|---|---|
| Key establishment | 25 | **25** | Untouched — the retrospective argument |
| Data lifetime | 20 | **20** | Untouched — the report's central argument |
| Operational access | — | **15** | New |
| Exposure surface | 15 | **10** | A raw host count; operational access measures what *kind* of surface, which is the more informative half |
| Certificate posture | 15 | **12** | Forward-only, already deliberately below key establishment |
| Transport hygiene | 15 | **11** | Present-day, scored for programme credibility not quantum exposure |
| Surface discipline | 10 | **7** | Overlaps directly — a reachable dev host and a reachable operator surface are adjacent observations |

**Every existing score moves.** That is what the version stamp is for:
`getBoardMetrics` suppresses the trend across the boundary rather than
presenting the shift as progress. Expect one suppressed trend per domain.

Measured on a worked critical-infrastructure estate:

```
with network scan     70 / 100  HIGH     complete
without               55 /  85  MEDIUM   operational access unassessed
```

The band moves when the network scan runs. That is correct — and it is the
argument for running it.

Calibration across estates, so the dimension is not a constant:

```
no operator surface at all                  0 / 15
ordinary SaaS: web + SSH bastion, classical 7 / 15
same estate after hybrid SSH KEX            4 / 15
Kubernetes API + bastion exposed           10 / 15
utility: OT, directory, VPN, telnet        15 / 15
```

## 3. `server.js` — the patch you need to apply

**a. Require it**

```js
const { assessDNEL } = require('./dnel');
```

**b. `/api/network-scan` — attach the block and fold in the findings**

After the scan result is built, before you respond:

```js
// Operator surfaces come from open ports, so DNEL is computed here.
// req.body.hosts already carries the TLS blocks assessDNEL needs.
result.dnel = assessDNEL({ hosts: req.body.hosts || [] }, result);
result.findings = (result.findings || []).concat(result.dnel.findings);
result.summary.bySeverity = ['critical','high','medium','low','info']
  .reduce((m, s) => (m[s] = result.findings.filter(f => f.severity === s).length, m), {});
result.summary.totalFindings = result.findings.length;
```

**c. `/api/report` — pass the network data through**

`buildInput` gained a fourth argument:

```js
const input = buildInput(scanResult, httpData, profile, networkData);
```

and the profile check becomes context-aware, so an estate with no operator
surface is not blocked on a rate for work it does not need:

```js
const dnelAssessed = !!(input.dnel && input.dnel.operator_surface_hosts > 0);
const outstanding = reportProfile.missing(profile, { accessTrack: dnelAssessed });
if (outstanding.length) return res.status(409).json({ missing: outstanding });
```

**d. `/api/cbom/persist`** — no change. It already forwards `networkData`, which
`cbom.js` now actually uses.

## 4. Two things to know before you deploy

**`npm ci` will fail.** `package.json` asks for `docx: ^9.7.1`; `package-lock.json`
pins `8.5.0` and its root range says `^8.5.0`. The lock does not satisfy the
manifest, which is a hard error for `npm ci` and a silent lock rewrite for
`npm install`. Run `npm install docx@^9.7.1` and commit the regenerated lock. I
built and verified the report against 9.7.1 and left both manifests as you sent
them rather than shipping a lockfile I could not fully regenerate.

**Existing report profiles stay valid.** The two new rate-card fields are only
required when a Class D exposure was actually raised, so a client whose estate
exposes no operator surface still builds without them.

## 5. Two pre-existing bugs found while wiring this

Both are key mismatches between what `qea-input.js` emits and what `qea-doc.js`
reads, and both printed the literal string **"undefined"** into every delivered
report. Neither throws, so nothing flagged them.

| Table | `qea-input` writes | `qea-doc` read | Effect |
|---|---|---|---|
| Exposure evidence | `label` | `item` | Left column of every evidence table in every exposure |
| Completion verification | `today` | `now` | The entire "Today" column |

Fixed in the renderer, accepting both keys, because hand-edited scan files and
`adapt-scan.js` may use either. The build now asserts the produced document
contains no `undefined`, `[object Object]` or `NaN` — worth keeping in CI.

A third, latent: `qea-input.js` read index components **positionally**
(`components[0]`, `[3]`, `[4]`, `[5]`). Inserting a seventh dimension would have
silently made each exposure print another dimension's points as its own. Now
read by name.

## 6. Verifying

```bash
npm run lint          # syntax across all modules, dnel.js included
node test-dnel.js     # scoring, projection, report input
node build-test.js    # builds a real .docx and validates it
```

`build-test.js` produces `/tmp/qea.docx`. Current state: validates, reconciles,
zero outstanding TODOs, fourteen sections including *Operational exposures*.

## 7. Still not observable

Named in the DNEL panel rather than scored as zero, because a low figure with
these open is a low figure about the part that was visible:

- **Crypto-agility constraint per asset** — field-upgradable / firmware-locked /
  certification-locked / hardware-locked. The single largest determinant of real
  DNEL exposure and the largest gap. Needs the attested import path already
  designed as Class D collection in your endpoint coverage matrix.
- **Identity provider signing posture** — OIDC discovery and JWKS publish
  `id_token` signing algorithms and key types directly, fetchable without
  credentials, parseable like a certificate. This is *literally* the operator
  authentication layer, and it is already scoped as **Phase 1** in that matrix.
  It is the cheapest large DNEL capability gain available.
- **Client certificate / mTLS requirement** — detectable by probing for a
  `CertificateRequest` in the handshake.
