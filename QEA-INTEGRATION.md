# QEA replaces the QTA

`POST /api/report` now builds the Quantum Exposure Assessment. The previous
generator (`report.js`) is out of the request path and marked retired; nothing
requires it, and it can be deleted once you are sure you no longer want the old
format for reference.

## New files

| File | Does |
|---|---|
| `qei.js` | The six-dimension index. Shared by the dashboard and the report |
| `qea-doc.js` | Builds the document. `validate(input)` then `build(input)` |
| `qea-input.js` | Maps scanner output into report input |
| `report-profile.js` | Stores the half of a report a scan cannot observe |
| `dnel.js` | Deploy Now, Exploit Later — the third risk axis. Single source of truth for operator-access exposure |

## The workflow

```bash
# 1. what does this client's report still need?
curl $API/api/report/profile/client.com

# 2. supply it (merged, not replaced — send only what changed)
curl -X PUT $API/api/report/profile/client.com \
  -H 'Content-Type: application/json' \
  -d '{"name":"Client Ltd","data_retention_years":12, ...}'

# 3. build
curl -X POST $API/api/report \
  -H 'Content-Type: application/json' \
  -d '{"scanResult":{...},"httpData":{...}}' -o report.docx
```

Step 3 returns **409 and a list of named fields** while anything is outstanding.
It does not return a partial document. A report missing the retention period is
not a draft — it is a document a board reads as finished, with a fabricated
exposure window in it.

## Why there is a profile at all

Four things in this report are not properties of the estate:

| Field | Why a scan cannot supply it |
|---|---|
| `data_retention_years` | Client-attested. Worth 20 index points and the basis of the exposure window. Get it in writing |
| `authorisation` | Your engagement reference. Active probing without recorded authority is an offence under the Computer Misuse Act 1990, which has no research defence |
| `rate_card.*` | Your rates, not a market estimate |
| `board.*` | The position, the ask, the decision |

The sensitivity selector in the UI carries a `dataRetainYears` default per
sector. That is a sector typical, not this client's obligation. It is fine for
pre-filling the profile and wrong as a substitute for asking.

## One index, not two

`cbom.js` used to compute its own QEI: KEX 0–50, an HNDL label 0–20, critical TLS
findings 0–15, dev hosts 0–10, DNS −10, SSH 0–5. The report computed a different
one. Both ran 0–100 and both were called a QEI, so the dashboard could read 61
and the delivered report 74 for the same estate on the same day.

`qei.js` is now the only one. The report's methodology won because it has a
data-lifetime dimension — retention against the CRQC estimate is the argument the
report makes, and a score blind to it cannot tell a 15-year firm from a 2-year one
with identical infrastructure — and because every dimension decomposes into
points, a maximum, and the observation behind it.

`QEI_METHOD_VERSION` is **3**. Version 1 was the retired scanner scorer;
version 2 was the six-dimension index before DNEL.

### Version 3 — operational access

A seventh dimension, worth 15 points, for Deploy Now, Exploit Later: the
exposure created when an adversary presents authentication material that is
genuinely valid because you issued it, rather than decrypting traffic (HNDL) or
forging an artifact (TNFL). Computed in `dnel.js` from the network scan's port
evidence; the arithmetic lives in `qei.js` so the projection can re-run it
against a modelled estate.

The 15 points came from exposure surface (15→10), certificate posture (15→12),
transport hygiene (15→11) and surface discipline (10→7) — dimensions that either
overlap with the new one or are explicitly not quantum exposures. Key
establishment and data lifetime are untouched.

**Every existing score moves.** One suppressed trend per domain is expected on
the first scan after this deploys, for the same reason a first retention entry
suppresses one: the numbers either side were not computed under the same rules.

Operational access is **unassessed without a network scan** and drops from the
denominator exactly as data lifetime does. An estate that was never port-scanned
is not an estate with no exposed operator surface. In practice this means a
scan-only report scores out of 85, and running the Network & Ports scan can move
the band — which is the argument for running it.

`buildInput` now takes a fourth argument:

```js
buildInput(scanResult, httpData, profile, networkData)
```

and `reportProfile.missing()` takes a context, so the two new operator-access
rate-card fields are only required when a Class D exposure was actually raised:

```js
reportProfile.missing(profile, { accessTrack: dnelWasAssessed })
```

### Scores out of 80

Retention is often unset, especially before the first client conversation. The
data-lifetime dimension is then marked **unassessed and dropped from the
denominator**: the dashboard shows `45 / 80`, never 45 dressed up as a score out
of 100. Board metrics carry `quantumExposureMax` and `quantumExposureComplete`,
and the dashboard bands proportionally — a fixed 70/40 threshold would read
58-of-80 as MODERATE when it is 72% and HIGH.

### Trends are suppressed when they would mislead

A trend across two different methodologies, or two different denominators, is a
number that looks like progress and means nothing. `getBoardMetrics` returns
`quantumExposureTrend: null` and `quantumExposureTrendSuppressed` with the reason.
Expect this once after setting a retention period for the first time: the previous
scan was out of 80 and the new one is out of 100.

## Class D — operational

Exposures are grouped by threat model. The fourth class is not a severity tier:

- **Class A — retrospective.** Delay increases the volume compromised, and
  nothing retires it.
- **Class B — forward.** Risk begins at Q-Day; historic material is unaffected.
- **Class C — present-day.** Unrelated to quantum, same programme.
- **Class D — operational.** The adversary neither decrypts nor forges. Delay
  increases the harvested credential volume as in Class A — but **rotation
  retires it**, which Class A has no equivalent of. That difference is why the
  operator-access track is scoped around credential lifetime and gateway
  placement rather than around cryptography alone.

## Known gap

`scope.handshakes_performed` still comes from the profile. The scanner does not
count handshakes, and that figure is load-bearing in the Method section — it is
the evidence that capability was established by negotiation rather than read off
an advertisement. Adding a counter to `scanDomain` would close the last blank in
the report that is not genuinely a judgement.
