# The old report is confirmed. Here is the one line that fixes it.

## The evidence

Three independent confirmations from the file you sent:

**1. The filename.** `CipherQ_QTA_cipherq.co_20260910.docx` — "QTA". The QEA
route emits `CipherQ_QEA_<domain>_<date>.docx`. The server named this file, and
it used the old generator's naming.

**2. The headings.** Executive Summary · Detailed Findings · DNS Security
Assessment · HTTP Security Assessment · Network & Protocol Security Assessment ·
TLS Scan Results · Recommended Roadmap · NIST PQC Control Mapping.

That is `report.js` exactly.

**3. What is absent.** Every marker of the new generator, counted across the
whole document:

```
Board summary               0     Class D                  0
Your exposure window        0     DNEL                     0
What we verified            0     Deploy Now               0
Exposures by threat model   0     operator surface         0
Operational exposures       0     Quantum Exposure Index   0
Sequence of work            0     Observation log          0
```

Zero occurrences of "Quantum Exposure Index" in a Quantum Threat Assessment. The
QEA renderer never ran.

**This is not a deployment problem.** `server.js` is calling `generateReport`.
Nothing in the package can change that — the fix has to be at the route.

---

## The fix: one line, added — nothing deleted

Express matches the **first** registered route. Register the QEA handler above
the existing one and it wins; the old handler is never reached. You do not need
to understand, edit or delete your current handler.

Anywhere in `server.js` **above** your existing `app.post('/api/report', …)`:

```js
app.post('/api/report', require('./qea-route').handler({
  reportProfile: require('./report-profile'),
}));
```

That is the whole change. To revert, delete the line.

### Proved end to end

I built a mock server calling the old generator, added that one line above it,
and posted a real scan:

```
status          : 200
old handler ran : false
filename        : CipherQ_QEA_example-utility.com_2026-09-10.docx
QEI header      : 70 / 100
sections header : 14

  yes   Board summary
  yes   Operational exposures
  yes   Class D
  yes   Deploy Now, Exploit Later
  absent (correct)   Executive Summary
```

### One caveat, and it matters

This works cleanly when your middleware is applied with `app.use(...)` — helmet,
rate limiting, body parsing, auth — because those still run before any route.

It does **not** carry middleware attached inline to the route itself. If your
line looks like:

```js
app.post('/api/report', requireAuth, rateLimit, async (req, res) => { … });
```

then repeat those in the shadowing line, or the QEA route will be reachable
without them:

```js
app.post('/api/report', requireAuth, rateLimit,
  require('./qea-route').handler({ reportProfile: require('./report-profile') }));
```

Check that before deploying. Losing an auth check is a far worse bug than the
one being fixed.

If your profiles are tenant-scoped:

```js
app.post('/api/report', require('./qea-route').handler({
  reportProfile: require('./report-profile'),
  loadProfile: (domain, req) => require('./report-profile').read(domain, req.tenantId),
}));
```

---

## Then confirm

The new filename is the fastest tell — **`CipherQ_QEA_`**, not `QTA`. Or without
opening anything:

```bash
curl -sI -X POST https://…/api/report -H 'Content-Type: application/json' \
     -d @payload.json | grep -i x-cipherq
```

```
X-CipherQ-QEI: 70
X-CipherQ-QEI-Max: 100
X-CipherQ-Sections: 14
```

- **14 sections** — working.
- **13 sections** — working, but `networkData` is not in the POST body.
- **No `X-CipherQ` headers at all** — the shadowing line is below the existing
  route, not above it. Move it up.

Expect a **409** on the first request naming the report-profile fields; that is
the gate working, not a failure.

---

## Still worth doing once this is in

Tidy the old route away rather than leaving it shadowed — a dead handler that
looks live is exactly how someone re-introduces this in six months. When you
delete it, `report.js` can go too unless something else uses it.

And send me `server.js`. Everything above is written blind against an interface;
with the file I would just make the edit.
