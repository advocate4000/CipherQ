# CipherQ — QEA report + DNEL

One package. Copy every file into your CipherQ folder, overwriting when asked.

```bash
tar -xzf cipherq-qea-dnel.tar.gz
cp -r cipherq-qea-dnel/* /path/to/your/cipherq/
cd /path/to/your/cipherq
npm install          # required — see note below
npm run preflight    # 16 checks; all must pass
```

Then restart. The boot log will end with:

```
[CipherQ] Report generator: qea-doc (QEA, method v3) — three-axis, DNEL enabled
```

That line is how you know which generator is live.

**`npm install` is not optional.** Your `package-lock.json` pinned `docx` at
8.5.0 while `package.json` asked for `^9.7.1`. That is a hard `npm ci` failure —
if your deploy runs `npm ci` it would not have built at all. The lock in this
package is regenerated and correct.

---

## First report will return 409. That is the gate, not a fault.

The QEA report puts a number, a cost and a recommendation in front of a board,
so it will not build until it has the inputs no scanner can observe. The 409
names every missing field and why it matters.

```bash
node set-profile.js cipherq.co                          # what is missing
node set-profile.js cipherq.co profile-template.json    # send it
```

Edit `profile-template.json`, run again, repeat until it says complete. Add
`--url https://your-host` if the server is not on localhost:3000.

A value starting with **`TODO`** counts as unset, so you can send the template
immediately and it will accept what is real while still asking for the rest. A
placeholder can never print in a delivered report as though it were an answer.

Of the 24 fields, about eight are genuinely judgement calls: `data_retention_years`
(worth 20 index points and it sets the exposure window), `authorisation`, the
rate card, and the six `board.*` fields. Those are left as TODO deliberately —
they are yours to state, not mine to invent.

---

## What changed

| File | Change |
|---|---|
| `server.js` | `/api/report` now calls the QEA generator, not `report.js`. **`GET`/`PUT /api/report/profile/:domain` added — these did not exist**, so the 409's own instructions used to 404. `/api/network-scan` attaches the DNEL block. Boot banner names the generator. |
| `qea-route.js` | **New.** The `/api/report` handler: profile gate, validation, filename, error shapes. |
| `dnel.js` | **New.** The DNEL model — surface classification, per-host scoring, findings. |
| `qea-input.js` | Takes `networkData`; emits Class D and the operator-access track; now emits `qei_max` and `complete` |
| `qea-doc.js` | Renders Class D and *Operational exposures*; **prints the real denominator** instead of a hardcoded `/ 100`; glossary corrected to seven dimensions |
| `qei.js` | METHOD_VERSION 3 — seventh dimension, *Operational access*, max 15 |
| `report-profile.js` | `rate_card.access_low` / `access_high`, required only where a Class D exposure was raised |
| `cbom.js` | Passes `networkData` into `deriveFacts` — it was accepted and ignored |
| `index.html` | Three-axis strip, DNEL tab, DNEL in the CycloneDX export, four CycloneDX schema fixes, status ticker rebuilt, type floor raised across the UI |
| `package.json` / `package-lock.json` | `docx ^9.7.1`, lock regenerated, test tooling moved to devDependencies |

**Not in this package:** `scanner.js`, `ssrf-guard.js`, `vendor.js`,
`dns-security.js`, `http-security.js`, `network-security.js`,
`internal-scanner.js`, `report.js`. They are unchanged — keep yours. This is why
you copy the package *over* your repo rather than deploying it alone.

`report.js` is now unreferenced. Delete it once you no longer want the old
format for comparison.

---

## Four bugs fixed along the way

**The report printed the wrong denominator.** `qei.js` removes unassessed
dimensions from the denominator rather than scoring them zero, so without a
network scan the maximum is 85. But `qea-input.js` never emitted it and
`qea-doc.js` hardcoded `/ 100`. Every report built without a network scan
**understated the estate** — 55/100 reads as mid-range; 55/85 is most of the way
to HIGH.

**The CBOM never reported the certificate signature algorithm.**
`certSig.algorithm` does not exist; every other module reads `.name`. It fell
back to `'unknown'` on every host, for the one property carrying the TNFL
argument.

**The CycloneDX export was schema-invalid** — and had been since it was written.
`assetType: 'protocol'` carried `algorithmProperties` (which belongs to
`assetType: 'algorithm'`), plus a `tlsData` object that is not a CycloneDX
field. No component had a `bom-ref`, so every `affects[].ref` was a dangling
pointer. And the enum is `related-crypto-material`, not `relatedCryptoMaterial`.

**The glossary said "six weighted dimensions."** Seven since METHOD_VERSION 3.

---

## Verifying

```bash
npm run preflight        # 16 checks — modules, deps, scoring, a real .docx
npm test                 # scoring, projection, report input, document build
node validate-cbom.js ~/Downloads/CipherQ_CBOM_yourdomain_2026-09-10.cdx.json
```

`validate-cbom.js` checks an export against the official CycloneDX 1.6 schema
plus referential integrity. Worth adding to CI — it would have caught the
`relatedCryptoMaterial` error the day it was written.

**Confirming the report is the new one:** the filename reads `CipherQ_QEA_`, not
`CipherQ_QTA_`. Or check the response headers:

```
X-CipherQ-QEI: 70
X-CipherQ-QEI-Max: 100
X-CipherQ-Sections: 14
```

14 sections including *Operational exposures* means it is working. 13 means the
network scan did not run — which is a legitimate state, and the report says so
by scoring out of 85 rather than 100.

---

## Two things that will surprise you on first run

**Every existing score moves.** METHOD_VERSION 2 → 3 rebalanced all seven
dimensions to make room for *Operational access*. `getBoardMetrics` suppresses
the trend across the version boundary rather than presenting the shift as
progress. Expect one suppressed trend per domain. That is correct.

**The report profile is per domain**, stored under `CBOM_DATA_DIR` (defaults to
a temp directory). On a host with ephemeral storage — Render's free tier, for
one — profiles will not survive a restart. Set `CBOM_DATA_DIR` to a persistent
disk if you want them to last.
