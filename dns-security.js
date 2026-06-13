'use strict';

/**
 * CipherQ DNS Security Scanner
 * Checks: zone transfer (AXFR), DNSSEC, SPF/DKIM/DMARC, CAA,
 *         dangling DNS / subdomain takeover, open resolver, PTR consistency
 */

const net    = require('net');
const dns    = require('dns').promises;
const https  = require('https');

// ─── Subdomain takeover fingerprints ─────────────────────────────────────────
// Maps a CNAME target pattern to the service and a known "unclaimed" response
// string. If we see the CNAME target AND the HTTP body contains the signature,
// the resource is unclaimed and the subdomain is takeable.
const TAKEOVER_SIGNATURES = [
  { service: 'GitHub Pages',      pattern: /\.github\.io$/i,              sig: "There isn't a GitHub Pages site here" },
  { service: 'Heroku',            pattern: /\.herokudns\.com$/i,           sig: 'No such app' },
  { service: 'Heroku',            pattern: /\.herokuapp\.com$/i,           sig: 'No such app' },
  { service: 'AWS S3',            pattern: /\.s3\.amazonaws\.com$/i,       sig: 'NoSuchBucket' },
  { service: 'AWS CloudFront',    pattern: /\.cloudfront\.net$/i,          sig: 'Bad request' },
  { service: 'Netlify',           pattern: /\.netlify\.app$/i,             sig: "Not found" },
  { service: 'Netlify',           pattern: /\.netlify\.com$/i,             sig: 'Not found' },
  { service: 'Fastly',            pattern: /\.fastly\.net$/i,              sig: 'Fastly error: unknown domain' },
  { service: 'Azure Websites',    pattern: /\.azurewebsites\.net$/i,       sig: 'not found' },
  { service: 'Azure CDN',         pattern: /\.azureedge\.net$/i,           sig: 'not found' },
  { service: 'Azure Traffic Mgr', pattern: /\.trafficmanager\.net$/i,      sig: 'not found' },
  { service: 'Shopify',           pattern: /\.myshopify\.com$/i,           sig: "Sorry, this shop is currently unavailable" },
  { service: 'Tumblr',            pattern: /\.tumblr\.com$/i,              sig: "There's nothing here" },
  { service: 'WordPress.com',     pattern: /\.wordpress\.com$/i,           sig: "Do you want to register" },
  { service: 'Ghost',             pattern: /\.ghost\.io$/i,                sig: "The thing you were looking for is no longer here" },
  { service: 'Zendesk',           pattern: /\.zendesk\.com$/i,             sig: "Help Center Closed" },
  { service: 'Freshdesk',         pattern: /\.freshdesk\.com$/i,           sig: "There is no helpdesk here" },
  { service: 'UserVoice',         pattern: /\.uservoice\.com$/i,           sig: "This UserVoice subdomain is currently available" },
  { service: 'Surge.sh',          pattern: /\.surge\.sh$/i,                sig: "project not found" },
  { service: 'Cargo',             pattern: /\.cargocollective\.com$/i,     sig: "404 Not Found" },
  { service: 'Agile CRM',         pattern: /\.agilecrm\.com$/i,            sig: "Sorry, this page is no longer available" },
  { service: 'Pingdom',           pattern: /\.pingdom\.com$/i,             sig: "This public report page has been removed" },
  { service: 'Readme.io',         pattern: /\.readme\.io$/i,               sig: "Project doesnt exist" },
  { service: 'Intercom',          pattern: /\.intercom\.help$/i,           sig: "This page is reserved for artistic insight" },
  { service: 'Webflow',           pattern: /\.webflow\.io$/i,              sig: "The page you are looking for doesn't exist" },
  { service: 'Anima',             pattern: /\.animaapp\.io$/i,             sig: "The page you are looking for does not exist" },
  { service: 'Fly.io',            pattern: /\.fly\.dev$/i,                 sig: "404" },
  { service: 'Render',            pattern: /\.onrender\.com$/i,            sig: "not found" },
  { service: 'DigitalOcean App',  pattern: /\.ondigitalocean\.app$/i,      sig: "no app" },
  { service: 'Vercel',            pattern: /\.vercel\.app$/i,              sig: "The deployment could not be found" },
  { service: 'Pantheon',          pattern: /\.pantheonsite\.io$/i,         sig: "404 error unknown site" },
  { service: 'SmartJobBoard',     pattern: /\.smartjobboard\.com$/i,       sig: "This job board website is either expired" },
  { service: 'Campaign Monitor',  pattern: /\.createsend\.com$/i,          sig: "CNAME" },
  { service: 'HubSpot',          pattern: /\.hs-sites\.com$/i,             sig: "does not exist" },
  { service: 'Squarespace',       pattern: /\.squarespace\.com$/i,         sig: "No Such Account" },
];

// ─── Utility: HTTP body fetch (no TLS verification, for takeover checks) ─────
function fetchHTTPBody(hostname, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const http = require('http');
    const req = http.request(
      { host: hostname, port: 80, path: '/', method: 'GET', timeout: timeoutMs },
      (res) => {
        let body = '';
        res.on('data', c => { body += c; if (body.length > 4096) res.destroy(); });
        res.on('end', () => resolve({ statusCode: res.statusCode, body, headers: res.headers }));
      }
    );
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// ─── 1. Zone Transfer (AXFR) ─────────────────────────────────────────────────
// Sends a raw DNS AXFR request over TCP to each nameserver.
// A successful zone transfer leaks the entire DNS zone.

function attemptAXFR(nameserver, domain, timeoutMs = 8000) {
  return new Promise((resolve) => {
    // Build DNS AXFR query packet
    const txid     = Math.floor(Math.random() * 65535);
    const labels   = domain.split('.');
    let qname = Buffer.alloc(0);
    for (const label of labels) {
      const len = Buffer.alloc(1); len.writeUInt8(label.length, 0);
      qname = Buffer.concat([qname, len, Buffer.from(label)]);
    }
    qname = Buffer.concat([qname, Buffer.from([0])]);

    const header = Buffer.alloc(12);
    header.writeUInt16BE(txid, 0);   // transaction ID
    header.writeUInt16BE(0x0000, 2); // flags: standard query
    header.writeUInt16BE(1, 4);      // QDCOUNT = 1
    header.writeUInt16BE(0, 6);      // ANCOUNT
    header.writeUInt16BE(0, 8);      // NSCOUNT
    header.writeUInt16BE(0, 10);     // ARCOUNT

    const qtype  = Buffer.from([0x00, 0xFC]); // AXFR = 252
    const qclass = Buffer.from([0x00, 0x01]); // IN

    const query = Buffer.concat([header, qname, qtype, qclass]);

    // DNS over TCP: 2-byte length prefix
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(query.length, 0);
    const packet = Buffer.concat([lenBuf, query]);

    const sock = new net.Socket();
    let data = Buffer.alloc(0);
    let resolved = false;

    const done = (result) => {
      if (!resolved) { resolved = true; sock.destroy(); resolve(result); }
    };

    sock.setTimeout(timeoutMs);
    sock.connect(53, nameserver, () => { sock.write(packet); });

    sock.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      // A real zone transfer returns multiple responses; if we get more than
      // 512 bytes of response to an AXFR query the transfer is open
      if (data.length > 512) {
        done({ vulnerable: true, nameserver, bytesReceived: data.length });
      }
    });

    sock.on('timeout', () => done({ vulnerable: false, nameserver, reason: 'timeout' }));
    sock.on('error',   (e) => done({ vulnerable: false, nameserver, reason: e.code || e.message }));
    sock.on('end',     () => {
      // Check response: if RCODE is 0 (NOERROR) and we got records, it's open
      if (data.length > 14) {
        const rcode = data[3] & 0x0F; // bits 0-3 of byte 3 (after length prefix)
        const ancount = data.readUInt16BE(8);
        if (rcode === 0 && ancount > 0) {
          done({ vulnerable: true, nameserver, bytesReceived: data.length });
        } else {
          done({ vulnerable: false, nameserver, rcode, reason: rcode === 9 ? 'NOTAUTH' : rcode === 5 ? 'REFUSED' : `RCODE=${rcode}` });
        }
      } else {
        done({ vulnerable: false, nameserver, reason: 'no data' });
      }
    });
  });
}

async function checkZoneTransfer(domain) {
  const result = { domain, nameservers: [], findings: [] };

  let nsRecords = [];
  try { nsRecords = await dns.resolveNs(domain); } catch {}

  if (nsRecords.length === 0) {
    result.findings.push({
      id: 'DNS-NO-NS',
      severity: 'medium',
      area: 'dns-zone',
      title: 'No NS records found for domain',
      detail: `No authoritative nameservers found for ${domain}. This may indicate a DNS misconfiguration or that the domain is not delegated.`,
      recommendation: 'Verify DNS delegation and nameserver configuration.',
    });
    return result;
  }

  // Resolve each nameserver to an IP
  const nsResults = await Promise.allSettled(
    nsRecords.map(async (ns) => {
      let ips = [];
      try { ips = await dns.resolve4(ns); } catch {}
      return { ns, ips };
    })
  );

  const nameservers = nsResults
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value)
    .filter(r => r.ips.length > 0);

  result.nameservers = nameservers.map(n => ({ ns: n.ns, ip: n.ips[0] }));

  // Attempt AXFR against each nameserver IP
  const axfrResults = await Promise.all(
    nameservers.map(({ ns, ips }) => attemptAXFR(ips[0], domain).then(r => ({ ...r, nsHostname: ns })))
  );

  const vulnerable = axfrResults.filter(r => r.vulnerable);

  if (vulnerable.length > 0) {
    result.findings.push({
      id: 'DNS-AXFR-OPEN',
      severity: 'critical',
      area: 'dns-zone',
      title: 'DNS zone transfer (AXFR) is permitted',
      detail: `Nameserver(s) ${vulnerable.map(r => r.nsHostname).join(', ')} responded to an AXFR (zone transfer) request. This leaks the complete DNS zone — every hostname, IP address, mail server, and internal subdomain — to any party that asks. This is a well-known reconnaissance technique used in the initial stages of targeted attacks.`,
      recommendation: 'Restrict AXFR to authorised secondary nameservers only, by IP ACL. Disable unauthenticated AXFR immediately.',
      priority: 'P1',
      nistRef: 'SC-20 · SC-21 · SI-3 | CIS Control 9',
    });
  } else {
    result.findings.push({
      id: 'DNS-AXFR-REFUSED',
      severity: 'info',
      area: 'dns-zone',
      title: 'Zone transfer (AXFR) correctly refused',
      detail: `All ${nsRecords.length} nameserver(s) refused the zone transfer request. Results: ${axfrResults.map(r => `${r.nsHostname}: ${r.reason || 'refused'}`).join(', ')}.`,
    });
  }

  result.axfrDetails = axfrResults;
  return result;
}

// ─── 2. DNSSEC ───────────────────────────────────────────────────────────────

async function checkDNSSEC(domain) {
  const result = { domain, findings: [] };

  let dnskeyRecords = [];
  let dsRecords     = [];
  let rrsigRecords  = [];

  try { dnskeyRecords = await dns.resolve(domain, 'DNSKEY'); } catch {}
  try { dsRecords     = await dns.resolve(domain, 'DS');     } catch {}
  try { rrsigRecords  = await dns.resolve(domain, 'RRSIG');  } catch {}

  result.hasDNSKEY = dnskeyRecords.length > 0;
  result.hasDS     = dsRecords.length > 0;
  result.hasRRSIG  = rrsigRecords.length > 0;

  const signed = result.hasDNSKEY || result.hasDS || result.hasRRSIG;

  if (!signed) {
    result.findings.push({
      id: 'DNS-NO-DNSSEC',
      severity: 'medium',
      area: 'dnssec',
      title: 'DNSSEC not deployed',
      detail: `${domain} has no DNSKEY, DS, or RRSIG records. Without DNSSEC, DNS responses can be spoofed (cache poisoning / Kaminsky attack). An attacker in a position to inject forged DNS responses can redirect clients to attacker-controlled servers without their knowledge, bypassing TLS entirely if a rogue certificate is also obtained.`,
      recommendation: 'Enable DNSSEC signing at your DNS registrar or DNS provider. Publish DS records at the parent zone. Use RSA-2048 or ECDSA P-256 as a minimum; note that DNSSEC algorithm selection is also subject to the post-quantum migration timeline.',
      nistRef: 'SC-20 · SC-21 | NIST SP 800-81-2',
    });
  } else if (result.hasDNSKEY && !result.hasDS) {
    result.findings.push({
      id: 'DNS-DNSSEC-PARTIAL',
      severity: 'medium',
      area: 'dnssec',
      title: 'DNSSEC key present but DS record missing at parent',
      detail: `${domain} has DNSKEY records but no DS record at the parent zone. The chain of trust is broken — DNSSEC validation will fail for resolvers that check the parent, making the signing functionally useless from a security standpoint.`,
      recommendation: 'Publish the DS record at the parent registrar to complete the chain of trust.',
      nistRef: 'SC-20 · SC-21 | NIST SP 800-81-2',
    });
  } else {
    result.findings.push({
      id: 'DNS-DNSSEC-OK',
      severity: 'info',
      area: 'dnssec',
      title: 'DNSSEC appears deployed',
      detail: `DNSKEY: ${result.hasDNSKEY ? 'present' : 'absent'} · DS: ${result.hasDS ? 'present' : 'absent'} · RRSIG: ${result.hasRRSIG ? 'present' : 'absent'}.`,
    });
  }

  return result;
}

// ─── 3. Email authentication: SPF, DKIM, DMARC ───────────────────────────────

function parseSPF(txtRecords) {
  const spf = txtRecords.find(r => r.startsWith('v=spf1'));
  if (!spf) return null;

  const mechanisms = spf.split(' ').filter(Boolean);
  const hasAll = mechanisms.find(m => m.match(/^[+-~?]all$/i));
  const qualifier = hasAll ? hasAll[0] : null;

  return {
    raw: spf,
    qualifier,
    // +all = anyone can send (dangerous), ?all = neutral, ~all = softfail, -all = hardfail (correct)
    risk: qualifier === '+' ? 'critical' :
          qualifier === '?' ? 'high' :
          qualifier === '~' ? 'medium' :
          qualifier === '-' ? 'none' : 'high',
    includes: mechanisms.filter(m => m.startsWith('include:')).map(m => m.slice(8)),
    redirects: mechanisms.find(m => m.startsWith('redirect=')),
    lookupCount: mechanisms.filter(m =>
      m.startsWith('include:') || m.startsWith('a:') || m.startsWith('mx') ||
      m.startsWith('ptr') || m.startsWith('exists:') || m.startsWith('redirect=')
    ).length,
  };
}

function parseDMARC(txtRecords) {
  const dmarc = txtRecords.find(r => r.startsWith('v=DMARC1'));
  if (!dmarc) return null;

  const pairs = {};
  for (const part of dmarc.split(';').map(s => s.trim()).filter(Boolean)) {
    const [k, v] = part.split('=');
    if (k && v) pairs[k.trim().toLowerCase()] = v.trim().toLowerCase();
  }

  return {
    raw: dmarc,
    policy: pairs.p || null,
    subdomainPolicy: pairs.sp || pairs.p || null,
    pct: parseInt(pairs.pct || '100', 10),
    rua: pairs.rua || null,
    ruf: pairs.ruf || null,
    aspf: pairs.aspf || 'r',
    adkim: pairs.adkim || 'r',
  };
}

async function checkEmailSecurity(domain) {
  const result = { domain, findings: [] };

  // Fetch TXT records for the domain
  let domainTxt = [];
  try { domainTxt = (await dns.resolveTxt(domain)).flat(); } catch {}

  // Fetch DMARC record from _dmarc subdomain
  let dmarcTxt = [];
  try { dmarcTxt = (await dns.resolveTxt(`_dmarc.${domain}`)).flat(); } catch {}

  // ── SPF ──────────────────────────────────────────────────────────────────
  const spfRecords = domainTxt.filter(r => r.startsWith('v=spf1'));

  if (spfRecords.length === 0) {
    result.findings.push({
      id: 'EMAIL-NO-SPF',
      severity: 'high',
      area: 'email-security',
      title: 'No SPF record found',
      detail: `${domain} has no SPF (Sender Policy Framework) TXT record. Without SPF, any mail server can send email claiming to be from this domain. SPF allows receiving mail servers to verify that incoming mail from a domain comes from a host authorised by that domain's administrators.`,
      recommendation: 'Publish a v=spf1 record listing authorised mail senders. End with "-all" (hardfail) to reject unauthorised senders.',
      nistRef: 'SI-8 · SC-5 | RFC 7208',
    });
  } else if (spfRecords.length > 1) {
    result.findings.push({
      id: 'EMAIL-MULTIPLE-SPF',
      severity: 'high',
      area: 'email-security',
      title: 'Multiple SPF records found (invalid)',
      detail: `${domain} has ${spfRecords.length} SPF records. RFC 7208 explicitly forbids multiple SPF records — the behaviour is undefined and many receivers will reject email from the domain entirely or treat SPF as permerror.`,
      recommendation: 'Consolidate into a single v=spf1 TXT record.',
      nistRef: 'SI-8 | RFC 7208 §3.2',
    });
  } else {
    const spf = parseSPF(spfRecords);
    result.spf = spf;

    if (spf.risk === 'critical') {
      result.findings.push({
        id: 'EMAIL-SPF-PLUS-ALL',
        severity: 'critical',
        area: 'email-security',
        title: 'SPF record uses "+all" — anyone can spoof this domain',
        detail: `The SPF record ends with "+all", which authorises every mail server on the internet to send email as ${domain}. This completely negates the purpose of SPF and enables trivial email spoofing.`,
        recommendation: 'Replace "+all" with "-all" (hardfail) immediately.',
        priority: 'P1',
        nistRef: 'SI-8 | RFC 7208',
      });
    } else if (spf.risk === 'high') {
      result.findings.push({
        id: 'EMAIL-SPF-NEUTRAL',
        severity: 'high',
        area: 'email-security',
        title: 'SPF record uses "?all" — neutral, provides no protection',
        detail: `The SPF record ends with "?all" (neutral). This explicitly states no policy for senders not listed — most receivers treat this the same as no SPF at all. Email spoofing is not prevented.`,
        recommendation: 'Replace "?all" with "-all" (hardfail). If mail sources are uncertain, use "~all" as a temporary measure and work toward "-all".',
        nistRef: 'SI-8 | RFC 7208',
      });
    } else if (spf.risk === 'medium') {
      result.findings.push({
        id: 'EMAIL-SPF-SOFTFAIL',
        severity: 'low',
        area: 'email-security',
        title: 'SPF uses "~all" (softfail) — consider upgrading to "-all"',
        detail: `SPF softfail (~all) marks non-listed senders as suspicious but does not instruct receivers to reject. Combined with a DMARC reject policy this provides reasonable protection, but "-all" is the correct posture.`,
        recommendation: 'Once all legitimate mail sources are documented in the SPF record, upgrade "~all" to "-all".',
        nistRef: 'SI-8 | RFC 7208',
      });
    } else {
      result.findings.push({
        id: 'EMAIL-SPF-OK',
        severity: 'info',
        area: 'email-security',
        title: 'SPF record present with hardfail (-all)',
        detail: `SPF record: ${spf.raw}`,
      });
    }

    // Check SPF lookup count (max 10 per RFC 7208)
    if (spf.lookupCount > 10) {
      result.findings.push({
        id: 'EMAIL-SPF-TOO-MANY-LOOKUPS',
        severity: 'medium',
        area: 'email-security',
        title: `SPF record exceeds 10 DNS lookup limit (${spf.lookupCount} lookups)`,
        detail: `RFC 7208 limits SPF evaluation to 10 DNS lookups. Records that exceed this cause a permerror, which many receivers treat as SPF fail. This can result in legitimate email being rejected.`,
        recommendation: 'Flatten the SPF record by resolving include chains to their constituent IP ranges and inlining them.',
        nistRef: 'SI-8 | RFC 7208 §4.6.4',
      });
    }
  }

  // ── DMARC ─────────────────────────────────────────────────────────────────
  if (dmarcTxt.length === 0) {
    result.findings.push({
      id: 'EMAIL-NO-DMARC',
      severity: 'high',
      area: 'email-security',
      title: 'No DMARC record found',
      detail: `${domain} has no DMARC record at _dmarc.${domain}. Without DMARC, receiving mail servers have no policy instruction for what to do with emails that fail SPF and DKIM checks. Spoofed emails from this domain reach inboxes uninstructed.`,
      recommendation: 'Publish a DMARC record at _dmarc.' + domain + ' with at minimum p=none for monitoring. Advance to p=quarantine and then p=reject as you gain confidence in your mail flows. Include a rua= reporting address.',
      nistRef: 'SI-8 | RFC 7489',
    });
  } else {
    const dmarc = parseDMARC(dmarcTxt);
    result.dmarc = dmarc;

    if (!dmarc) {
      result.findings.push({
        id: 'EMAIL-DMARC-INVALID',
        severity: 'medium',
        area: 'email-security',
        title: 'DMARC record present but could not be parsed',
        detail: `_dmarc.${domain} has a TXT record that does not parse as a valid DMARC record: "${dmarcTxt[0]}"`,
        recommendation: 'Correct the DMARC record syntax.',
      });
    } else if (dmarc.policy === 'none') {
      result.findings.push({
        id: 'EMAIL-DMARC-NONE',
        severity: 'medium',
        area: 'email-security',
        title: 'DMARC policy is "none" — monitoring only, no enforcement',
        detail: `DMARC policy p=none instructs receivers to take no action on failing messages. This is appropriate during initial deployment for monitoring, but provides no spoofing protection. Spoofed emails from ${domain} continue to reach inboxes.`,
        recommendation: `Analyse DMARC aggregate reports (rua=${dmarc.rua || 'not set'}). Once mail flows are understood, advance to p=quarantine, then p=reject.`,
        nistRef: 'SI-8 | RFC 7489',
      });
    } else if (dmarc.policy === 'quarantine') {
      result.findings.push({
        id: 'EMAIL-DMARC-QUARANTINE',
        severity: 'low',
        area: 'email-security',
        title: 'DMARC policy is "quarantine" — consider advancing to "reject"',
        detail: `p=quarantine sends failing messages to spam. This is good but p=reject is the strongest posture and should be the target.${dmarc.pct < 100 ? ` Current enforcement is at ${dmarc.pct}% of messages.` : ''}`,
        recommendation: 'Advance to p=reject once you are confident all legitimate mail passes DMARC.',
        nistRef: 'SI-8 | RFC 7489',
      });
    } else if (dmarc.policy === 'reject') {
      result.findings.push({
        id: 'EMAIL-DMARC-REJECT',
        severity: 'info',
        area: 'email-security',
        title: 'DMARC policy is "reject" — strongest protection',
        detail: `DMARC p=reject is correctly configured.${dmarc.pct < 100 ? ` Note: pct=${dmarc.pct} means only ${dmarc.pct}% of messages are subject to the reject policy.` : ''}${!dmarc.rua ? ' No aggregate reporting address (rua) configured — add one for visibility.' : ''}`,
      });
    }

    if (!dmarc?.rua) {
      result.findings.push({
        id: 'EMAIL-DMARC-NO-RUA',
        severity: 'low',
        area: 'email-security',
        title: 'DMARC has no aggregate reporting address (rua)',
        detail: 'Without a rua= reporting address, you receive no feedback on which mail sources are failing DMARC checks. This makes it difficult to detect spoofing attempts or misconfigured mail servers.',
        recommendation: 'Add rua=mailto:dmarc-reports@yourdomain.com (or a DMARC reporting service) to your DMARC record.',
        nistRef: 'SI-8 | RFC 7489',
      });
    }
  }

  // ── DKIM ──────────────────────────────────────────────────────────────────
  // DKIM selectors are not discoverable from DNS alone; check common ones
  const commonSelectors = ['default', 'dkim', 'mail', 'google', 'k1', 's1', 's2', 'selector1', 'selector2', 'smtp', 'email', 'mandrill', 'sendgrid', 'mailchimp', 'amazonses'];
  const dkimFound = [];

  await Promise.allSettled(
    commonSelectors.map(sel =>
      dns.resolveTxt(`${sel}._domainkey.${domain}`)
        .then(r => { if (r.flat().some(t => t.includes('v=DKIM1'))) dkimFound.push(sel); })
        .catch(() => {})
    )
  );

  result.dkimSelectors = dkimFound;

  if (dkimFound.length === 0) {
    result.findings.push({
      id: 'EMAIL-NO-DKIM',
      severity: 'medium',
      area: 'email-security',
      title: 'No DKIM records found at common selectors',
      detail: `No DKIM TXT records were found at the following selectors checked: ${commonSelectors.join(', ')}. This does not definitively mean DKIM is absent (custom selectors not in the list may be in use), but warrants verification. DKIM cryptographically signs outbound mail, allowing receivers to verify it was sent by an authorised server and was not modified in transit.`,
      recommendation: 'Verify DKIM is configured on your mail sending infrastructure. Ensure all mail services (G Suite, Microsoft 365, transactional email providers) have DKIM signing enabled and their selectors are published.',
      nistRef: 'SI-8 | RFC 6376',
    });
  } else {
    result.findings.push({
      id: 'EMAIL-DKIM-FOUND',
      severity: 'info',
      area: 'email-security',
      title: `DKIM records found at selectors: ${dkimFound.join(', ')}`,
      detail: `DKIM is configured. Selectors found: ${dkimFound.join(', ')}.`,
    });
  }

  return result;
}

// ─── 4. CAA records ───────────────────────────────────────────────────────────

async function checkCAA(domain) {
  const result = { domain, findings: [] };

  let caaRecords = [];
  try { caaRecords = await dns.resolve(domain, 'CAA'); } catch {}

  // Walk up the zone hierarchy (CAA inherits from parent)
  let parentCAA = [];
  const parts = domain.split('.');
  if (parts.length > 2) {
    const parent = parts.slice(1).join('.');
    try { parentCAA = await dns.resolve(parent, 'CAA'); } catch {}
  }

  result.caaRecords    = caaRecords;
  result.parentCAA     = parentCAA;
  result.effectiveCAA  = caaRecords.length > 0 ? caaRecords : parentCAA;

  if (result.effectiveCAA.length === 0) {
    result.findings.push({
      id: 'DNS-NO-CAA',
      severity: 'medium',
      area: 'caa',
      title: 'No CAA records — any CA can issue certificates for this domain',
      detail: `${domain} has no CAA (Certification Authority Authorisation) records, and none were found at the parent zone. Without CAA, any of the ~150 publicly trusted CAs can issue a certificate for this domain without restriction. A misissued certificate — whether through a rogue CA, compromised CA infrastructure, or social engineering — could enable MITM attacks even if your own certificate management is perfect.`,
      recommendation: 'Publish CAA records restricting certificate issuance to your chosen CA(s). Example: 0 issue "letsencrypt.org" / 0 issue "digicert.com". Include an iodef address for misissuance reports. This is a low-effort, high-value control.',
      nistRef: 'SC-17 | RFC 8659 | CA/Browser Forum Baseline Requirements §3.2.2.8',
    });
  } else {
    const issueTags  = result.effectiveCAA.filter(r => typeof r === 'object' ? r.critical === 0 : String(r).includes('issue'));
    const issuewild  = result.effectiveCAA.filter(r => String(r).includes('issuewild'));
    const iodef      = result.effectiveCAA.filter(r => String(r).includes('iodef'));

    result.findings.push({
      id: 'DNS-CAA-PRESENT',
      severity: 'info',
      area: 'caa',
      title: 'CAA records present',
      detail: `CAA records found (${caaRecords.length > 0 ? 'on domain' : 'inherited from parent'}). ${result.effectiveCAA.length} record(s).${iodef.length === 0 ? ' Note: no iodef record — consider adding one to receive misissuance reports.' : ''}`,
    });

    if (iodef.length === 0) {
      result.findings.push({
        id: 'DNS-CAA-NO-IODEF',
        severity: 'low',
        area: 'caa',
        title: 'CAA record has no iodef (misissuance reporting) tag',
        detail: 'The iodef tag instructs CAs to send a report when a certificate request fails the CAA check. Without it, attempted misissuance is silent.',
        recommendation: 'Add a CAA iodef record: 0 iodef "mailto:security@yourdomain.com"',
        nistRef: 'SC-17 | RFC 8659',
      });
    }
  }

  return result;
}

// ─── 5. Subdomain takeover ────────────────────────────────────────────────────

async function checkSubdomainTakeover(hostname) {
  const result = { hostname, findings: [] };

  // Get CNAME chain
  let cname = null;
  try {
    const cnames = await dns.resolveCname(hostname);
    cname = cnames[0] || null;
  } catch {}

  if (!cname) return result; // No CNAME = not takeable via this vector

  result.cname = cname;

  // Match against known takeover signatures
  const match = TAKEOVER_SIGNATURES.find(s => s.pattern.test(cname));
  if (!match) return result;

  result.service = match.service;

  // Fetch HTTP body and check for the "unclaimed" signature
  const http = await fetchHTTPBody(hostname);
  if (http && http.body && match.sig && http.body.toLowerCase().includes(match.sig.toLowerCase())) {
    result.findings.push({
      id: 'DNS-SUBDOMAIN-TAKEOVER',
      severity: 'critical',
      area: 'subdomain-takeover',
      title: `Subdomain takeover possible — ${match.service} resource unclaimed`,
      detail: `${hostname} has a CNAME to ${cname} (${match.service}), but the ${match.service} resource at that target appears to be unclaimed. The HTTP response body contains the signature "${match.sig}", which ${match.service} serves when no project/bucket/app is registered. An attacker can register the resource on ${match.service} and serve arbitrary content under your domain — bypassing your brand, security headers, and potentially stealing session cookies if the subdomain shares a parent domain with authenticated services.`,
      recommendation: `Either: (a) re-register the ${match.service} resource and point it to legitimate content, or (b) remove the DNS CNAME record for ${hostname} immediately.`,
      priority: 'P1',
      nistRef: 'CM-3 · CM-5 · SC-18 | OWASP Subdomain Takeover',
    });
  } else if (http === null) {
    // Couldn't reach it — CNAME pointing to dead service is still suspicious
    result.findings.push({
      id: 'DNS-DANGLING-CNAME',
      severity: 'high',
      area: 'subdomain-takeover',
      title: `Dangling CNAME to ${match.service} — possible takeover risk`,
      detail: `${hostname} has a CNAME to ${cname} (${match.service}), but the target could not be reached. If the ${match.service} resource is no longer registered, this subdomain may be claimable by an attacker.`,
      recommendation: `Verify whether the ${match.service} resource at ${cname} is still registered and active. If not, remove the CNAME from DNS.`,
      priority: 'P1',
      nistRef: 'CM-3 · CM-5 | OWASP Subdomain Takeover',
    });
  }

  return result;
}

// ─── 6. Open resolver ─────────────────────────────────────────────────────────

async function checkOpenResolver(nameserverIP) {
  return new Promise((resolve) => {
    // Send a DNS query for a well-known external domain to the nameserver.
    // If it responds with a valid answer, it's an open resolver.
    const socket = require('dgram').createSocket('udp4');
    let resolved = false;

    const done = (isOpen, reason) => {
      if (!resolved) {
        resolved = true;
        socket.close();
        resolve({ ip: nameserverIP, isOpen, reason });
      }
    };

    // Build a minimal DNS query for "google.com A"
    const query = Buffer.from([
      0x00, 0x01, // txid
      0x01, 0x00, // flags: recursion desired
      0x00, 0x01, // QDCOUNT = 1
      0x00, 0x00, // ANCOUNT
      0x00, 0x00, // NSCOUNT
      0x00, 0x00, // ARCOUNT
      0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // \x06google
      0x03, 0x63, 0x6f, 0x6d, 0x00,              // \x03com\x00
      0x00, 0x01, // QTYPE = A
      0x00, 0x01, // QCLASS = IN
    ]);

    socket.on('message', (msg) => {
      const ancount = msg.readUInt16BE(6);
      const rcode   = msg[3] & 0x0F;
      // If we got an answer with ANCOUNT > 0 and RCODE 0, it resolved for us
      done(ancount > 0 && rcode === 0, ancount > 0 ? 'resolved external query' : `rcode=${rcode}`);
    });

    socket.on('error', () => done(false, 'socket error'));

    socket.send(query, 53, nameserverIP, (err) => {
      if (err) done(false, 'send error');
    });

    setTimeout(() => done(false, 'timeout'), 4000);
  });
}

async function checkOpenResolvers(domain) {
  const result = { domain, findings: [] };

  let nsRecords = [];
  try { nsRecords = await dns.resolveNs(domain); } catch {}

  if (nsRecords.length === 0) return result;

  // Resolve NS to IPs
  const nsIPs = [];
  for (const ns of nsRecords) {
    try {
      const ips = await dns.resolve4(ns);
      if (ips[0]) nsIPs.push({ ns, ip: ips[0] });
    } catch {}
  }

  const resolverResults = await Promise.all(nsIPs.map(({ ns, ip }) =>
    checkOpenResolver(ip).then(r => ({ ...r, ns }))
  ));

  result.resolverResults = resolverResults;
  const openResolvers = resolverResults.filter(r => r.isOpen);

  if (openResolvers.length > 0) {
    result.findings.push({
      id: 'DNS-OPEN-RESOLVER',
      severity: 'high',
      area: 'dns-resolver',
      title: `Open DNS resolver detected on ${openResolvers.length} nameserver(s)`,
      detail: `Nameserver(s) ${openResolvers.map(r => `${r.ns} (${r.ip})`).join(', ')} are configured as open resolvers — they will recursively resolve DNS queries from any IP address. Open resolvers can be abused in DNS amplification DDoS attacks (a single small query generates a large response, which is directed at a victim's IP), and they expose internal DNS state to external parties.`,
      recommendation: 'Configure nameservers to only accept recursive queries from authorised IP ranges (your own infrastructure). Disable open recursion on all authoritative nameservers.',
      nistRef: 'SC-5 · SC-20 | BCP 140 (RFC 5358)',
    });
  } else {
    result.findings.push({
      id: 'DNS-RESOLVER-RESTRICTED',
      severity: 'info',
      area: 'dns-resolver',
      title: 'Nameservers are not open resolvers',
      detail: `All ${nsIPs.length} nameserver(s) tested refused to recursively resolve external queries.`,
    });
  }

  return result;
}

// ─── 7. PTR / reverse DNS consistency ────────────────────────────────────────

async function checkPTR(hostname, aRecords) {
  const result = { hostname, findings: [] };
  if (!aRecords || aRecords.length === 0) return result;

  const ptrResults = await Promise.allSettled(
    aRecords.slice(0, 3).map(ip =>
      dns.reverse(ip).then(names => ({ ip, names })).catch(() => ({ ip, names: [] }))
    )
  );

  const ptrs = ptrResults
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);

  result.ptrs = ptrs;

  const mismatches = ptrs.filter(p =>
    p.names.length === 0 ||
    !p.names.some(n => n.toLowerCase().includes(hostname.split('.').slice(-2).join('.').toLowerCase()))
  );

  if (ptrs.some(p => p.names.length === 0)) {
    result.findings.push({
      id: 'DNS-NO-PTR',
      severity: 'info',
      area: 'dns-hygiene',
      title: `Missing PTR record for ${ptrs.filter(p => p.names.length === 0).map(p => p.ip).join(', ')}`,
      detail: 'Reverse DNS (PTR) records are missing for one or more IP addresses. Some mail servers reject email from IPs without PTR records. PTR records are also used in logging and incident response.',
      recommendation: 'Configure PTR records with your hosting provider or ISP for all externally-facing IP addresses.',
    });
  }

  return result;
}

// ─── Master DNS security scan ─────────────────────────────────────────────────

async function scanDNSSecurity(domain, hosts, opts = {}) {
  const { onProgress = null } = opts;

  const allFindings = [];
  const report = { domain, checks: {} };

  const step = (name, msg) => {
    if (onProgress) onProgress({ phase: 'dns-security', step: name, message: msg });
  };

  // Run domain-level checks in parallel where safe
  step('axfr',   'Testing zone transfer (AXFR)…');
  step('dnssec', 'Checking DNSSEC…');
  step('email',  'Analysing SPF / DKIM / DMARC…');
  step('caa',    'Checking CAA records…');
  step('resolver', 'Testing for open resolvers…');

  const [zoneXfer, dnssec, email, caa, openRes] = await Promise.all([
    checkZoneTransfer(domain),
    checkDNSSEC(domain),
    checkEmailSecurity(domain),
    checkCAA(domain),
    checkOpenResolvers(domain),
  ]);

  report.checks.zoneTransfer  = zoneXfer;
  report.checks.dnssec        = dnssec;
  report.checks.emailSecurity = email;
  report.checks.caa           = caa;
  report.checks.openResolver  = openRes;

  allFindings.push(
    ...zoneXfer.findings,
    ...dnssec.findings,
    ...email.findings,
    ...caa.findings,
    ...openRes.findings,
  );

  // Per-host checks: subdomain takeover + PTR
  step('takeover', 'Checking for subdomain takeover vulnerabilities…');

  const reachableHosts = hosts.filter(h => h.dns?.resolves);
  const takeoverResults = await Promise.all(
    reachableHosts.map(h => checkSubdomainTakeover(h.hostname))
  );

  const ptrResults = await Promise.all(
    reachableHosts
      .filter(h => h.dns?.aRecords?.length > 0)
      .map(h => checkPTR(h.hostname, h.dns.aRecords))
  );

  for (const r of [...takeoverResults, ...ptrResults]) {
    for (const f of r.findings) {
      allFindings.push({ ...f, hostname: r.hostname });
    }
  }

  report.checks.takeoverResults = takeoverResults;
  report.checks.ptrResults      = ptrResults;

  // Summary
  report.summary = {
    totalFindings: allFindings.length,
    bySeverity: {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high:     allFindings.filter(f => f.severity === 'high').length,
      medium:   allFindings.filter(f => f.severity === 'medium').length,
      low:      allFindings.filter(f => f.severity === 'low').length,
      info:     allFindings.filter(f => f.severity === 'info').length,
    },
    axfrVulnerable:      zoneXfer.findings.some(f => f.id === 'DNS-AXFR-OPEN'),
    dnssecDeployed:      dnssec.findings.some(f => f.id === 'DNS-DNSSEC-OK'),
    dmarcPolicy:         email.dmarc?.policy || 'missing',
    spfPresent:          !!email.spf,
    caaPresent:          caa.effectiveCAA?.length > 0,
    takeoverCount:       allFindings.filter(f => f.id === 'DNS-SUBDOMAIN-TAKEOVER').length,
    danglingCNAMECount:  allFindings.filter(f => f.id === 'DNS-DANGLING-CNAME').length,
    openResolverCount:   allFindings.filter(f => f.id === 'DNS-OPEN-RESOLVER').length,
  };

  return { report, findings: allFindings };
}

module.exports = {
  scanDNSSecurity,
  checkZoneTransfer,
  checkDNSSEC,
  checkEmailSecurity,
  checkCAA,
  checkSubdomainTakeover,
  checkOpenResolvers,
  checkPTR,
};
