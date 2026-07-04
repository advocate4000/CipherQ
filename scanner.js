'use strict';

/**
 * PQC Domain Scanner — Core Engine
 * Replicates the methodology from the gunnercooke Quantum Threat Assessment
 * Covers: TLS probe, KEX analysis, certificate posture, SNI matching,
 *         DNS surface enumeration, legacy protocol detection, HNDL risk rating
 */

const tls = require('tls');
const net = require('net');
const dns = require('dns').promises;
const { assertScannable } = require('./ssrf-guard');

// ─── Constants ───────────────────────────────────────────────────────────────

const TLS_PORT = 443;
const CONNECT_TIMEOUT_MS = 5000;  // reduced from 8000 — hung TCP connections are the main stall cause

// Algorithms known to be quantum-safe (KEX)
const PQ_KEX_PATTERNS = [
  /mlkem/i, /kyber/i, /x25519mlkem/i, /secp256r1mlkem/i, /secp384r1mlkem/i,
  /x25519kyber/i, /mlkem768/i, /mlkem1024/i
];

// Algorithms known to be quantum-vulnerable (KEX)
const CLASSICAL_KEX_PATTERNS = [
  /ecdhe/i, /dhe/i, /rsa/i, /x25519$/, /p-256/i, /secp256r1/i, /p-384/i
];

// Algorithms quantum-safe for symmetric (not threatened by Grover until < 256-bit)
const SAFE_SYMMETRIC = ['AES_256_GCM', 'AES_256_CCM', 'CHACHA20_POLY1305'];

// Certificate signature algorithms that are PQ
const PQ_SIG_PATTERNS = [/ml-dsa/i, /mldsa/i, /slh-dsa/i, /slhdsa/i, /fn-dsa/i, /fndsa/i, /dilithium/i, /falcon/i, /sphincs/i];

// Well-known CAs that currently DON'T issue PQ leaf certs (as of mid-2026)
const CLASSICAL_CA_PATTERNS = [
  /let's encrypt/i, /letsencrypt/i, /google trust/i, /digicert/i,
  /sectigo/i, /comodo/i, /globalsign/i, /entrust/i, /godaddy/i,
  /amazon/i, /cloudflare/i
];

// cPanel/hosting-default subdomain indicators
const HOSTING_DEFAULT_NAMES = [
  'mail', 'webmail', 'webdisk', 'cpanel', 'whm', 'ftp',
  'smtp', 'pop', 'imap', 'autodiscover', 'autoconfig'
];

// TLS versions and whether they're acceptable
const TLS_VERSION_RISK = {
  'TLSv1.3': { risk: 'none',     label: 'TLS 1.3' },
  'TLSv1.2': { risk: 'low',      label: 'TLS 1.2' },
  'TLSv1.1': { risk: 'critical', label: 'TLS 1.1 (deprecated RFC 8996)' },
  'TLSv1':   { risk: 'critical', label: 'TLS 1.0 (deprecated RFC 8996)' },
  'SSLv3':   { risk: 'critical', label: 'SSL 3.0 (POODLE)' },
};

// ─── Utility ─────────────────────────────────────────────────────────────────

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const expiry = new Date(dateStr);
  const now = new Date();
  return Math.round((expiry - now) / (1000 * 60 * 60 * 24));
}

// ─── OID map for signature algorithms ────────────────────────────────────────
// Maps DER signature algorithm OID bytes (hex) to human-readable names.
// This is the only reliable way to identify the *signing* algorithm rather
// than the *subject public key* type, which is what Node.js exposes.
const SIG_ALG_OIDS = {
  // RSA PKCS#1 v1.5
  '2a864886f70d010105': 'RSA-SHA1',
  '2a864886f70d01010b': 'RSA-SHA256',
  '2a864886f70d01010c': 'RSA-SHA384',
  '2a864886f70d01010d': 'RSA-SHA512',
  '2a864886f70d01010e': 'RSA-SHA224',
  // RSASSA-PSS
  '2a864886f70d01010a': 'RSA-PSS',
  // ECDSA
  '2a8648ce3d040103':  'ECDSA-SHA384',
  '2a8648ce3d040104':  'ECDSA-SHA512',
  '2a8648ce3d040301':  'ECDSA-SHA224',
  '2a8648ce3d040302':  'ECDSA-SHA256',
  // ML-DSA (FIPS 204) / Dilithium — NIST OIDs (draft 2024)
  '608648016503040303': 'ML-DSA-44',
  '608648016503040305': 'ML-DSA-65',
  '608648016503040306': 'ML-DSA-87',
  // SLH-DSA (FIPS 205) — NIST OIDs
  '608648016503040d01': 'SLH-DSA-SHA2-128s',
  '608648016503040d02': 'SLH-DSA-SHA2-128f',
  // Falcon (tentative IETF OIDs)
  '2b06010401da470f01': 'Falcon-512',
  '2b06010401da470f02': 'Falcon-1024',
};

const PQ_SIG_NAMES = new Set(['ML-DSA-44','ML-DSA-65','ML-DSA-87','SLH-DSA-SHA2-128s','SLH-DSA-SHA2-128f','Falcon-512','Falcon-1024']);
const ECDSA_NAMES  = new Set(['ECDSA-SHA224','ECDSA-SHA256','ECDSA-SHA384','ECDSA-SHA512']);
const RSA_NAMES    = new Set(['RSA-SHA1','RSA-SHA256','RSA-SHA384','RSA-SHA512','RSA-SHA224','RSA-PSS']);

/**
 * Extract the signature algorithm from the raw DER-encoded certificate.
 * The signatureAlgorithm field sits at the top of TBSCertificate (offset ≈5–30).
 * We scan for the OID tag (0x06) and match against our known map.
 * Falls back to public-key-type inference if DER is unavailable.
 */
function certSigAlgorithm(cert) {
  // Prefer DER parsing via Node's X509Certificate (Node 15.6+, available on 18+)
  if (cert._raw) {
    try {
      const crypto = require('crypto');
      if (crypto.X509Certificate) {
        const x509 = new crypto.X509Certificate(cert._raw);
        // x509 exposes no direct sigAlg property in older Node — but infoAccess
        // parsing gives us KeyUsage / SubjectPublicKeyInfo. We still need DER walk.
        // Walk the raw DER to find the first OID tag (0x06) after the outer SEQUENCE.
        const der = Buffer.from(cert._raw);
        // Skip outer SEQUENCE (tag 0x30, length) and TBSCertificate SEQUENCE.
        // The signatureAlgorithm comes after TBSCertificate, around byte 10-40.
        // We do a conservative scan: find all OID tags and match the first we know.
        for (let i = 0; i < Math.min(der.length - 4, 400); i++) {
          if (der[i] !== 0x06) continue;
          const oidLen = der[i + 1];
          if (oidLen < 3 || i + 2 + oidLen > der.length) continue;
          const oidHex = der.slice(i + 2, i + 2 + oidLen).toString('hex');
          const algName = SIG_ALG_OIDS[oidHex];
          if (algName) {
            if (PQ_SIG_NAMES.has(algName))  return { alg: 'PQ',    name: algName };
            if (ECDSA_NAMES.has(algName))   return { alg: 'ECDSA', name: algName };
            if (RSA_NAMES.has(algName))     return { alg: 'RSA',   name: algName };
          }
        }
      }
    } catch {}
  }

  // Fallback: infer from subject public key info (less accurate for sig alg,
  // but avoids the "RSA key / ECDSA signature" confusion in older Node paths)
  if (cert.exponent) return { alg: 'RSA',   name: `RSA-${cert.bits}` };
  if (cert.bits)     return { alg: 'ECDSA', name: `ECDSA-${cert.bits}` };

  // Last resort: pattern match the stringified cert for known PQ names
  const raw = JSON.stringify(cert);
  for (const p of PQ_SIG_PATTERNS) {
    if (p.test(raw)) return { alg: 'PQ', name: 'PQ (pattern match)' };
  }
  return { alg: 'unknown', name: 'unknown' };
}

function classifyKex(cipherName, protocol) {
  if (!cipherName) return { type: 'unknown', pqStatus: 'unknown', label: 'Unknown' };

  // TLS 1.3 cipher names don't encode KEX — it's negotiated separately
  // In TLS 1.3, Node.js doesn't expose the named group through getCipher()
  // We can check the cipher name and protocol together
  if (protocol === 'TLSv1.3') {
    // TLS 1.3 always uses ephemeral KEX (ECDHE or, if PQ, X25519MLKEM768 etc.)
    // Node doesn't expose the named group without native API extensions
    // We record this as "classical-likely" pending deeper enumeration
    return {
      type: 'ecdhe-ephemeral',
      pqStatus: 'classical-likely',
      label: 'ECDHE (group not enumerated — classical likely; see note)',
      note: 'TLS 1.3 KEX group requires deep enumeration. Hybrid PQ KEX (X25519MLKEM768) not detectable via standard socket API without OpenSSL extension.'
    };
  }

  // TLS 1.2 — cipher name encodes KEX
  if (/DHE/.test(cipherName) && !/ECDHE/.test(cipherName)) {
    return { type: 'ffdhe', pqStatus: 'classical', label: 'FFDHE (classical — quantum vulnerable)' };
  }
  if (/ECDHE/.test(cipherName)) {
    return { type: 'ecdhe', pqStatus: 'classical', label: 'ECDHE (classical — quantum vulnerable)' };
  }
  if (/RSA/.test(cipherName) && !/DHE/.test(cipherName)) {
    return { type: 'rsa-kex', pqStatus: 'classical', label: 'RSA key exchange (static — quantum vulnerable + no PFS)' };
  }

  return { type: 'unknown', pqStatus: 'unknown', label: cipherName };
}

function classifyCertSig(cert) {
  const { alg, name } = certSigAlgorithm(cert);
  switch (alg) {
    case 'RSA':
      return { algorithm: name, pqStatus: 'quantum-vulnerable', label: `${name} (quantum-vulnerable via Shor's algorithm)` };
    case 'ECDSA':
      return { algorithm: name, pqStatus: 'quantum-vulnerable', label: `${name} (quantum-vulnerable via Shor's algorithm)` };
    case 'PQ':
      return { algorithm: name, pqStatus: 'quantum-safe', label: `${name} — post-quantum signature, HNDL/TNFL risk mitigated on certificate` };
    default:
      return { algorithm: 'unknown', pqStatus: 'unknown', label: 'Signature algorithm could not be determined — deep enumeration recommended' };
  }
}

function isCAClassical(issuerO, issuerCN) {
  const s = `${issuerO || ''} ${issuerCN || ''}`;
  return CLASSICAL_CA_PATTERNS.some(p => p.test(s));
}

function sniMatch(hostname, certSubject, certSAN) {
  const cn = certSubject?.CN || '';
  const san = certSAN || '';

  // Exact match on CN
  if (cn.toLowerCase() === hostname.toLowerCase()) return { match: true, detail: `CN matches: ${cn}` };

  // Wildcard match on CN
  if (cn.startsWith('*.')) {
    const base = cn.slice(2).toLowerCase();
    const host = hostname.toLowerCase();
    if (host.endsWith('.' + base) || host === base) return { match: true, detail: `Wildcard CN matches: ${cn}` };
  }

  // SAN match
  const sans = san.split(',').map(s => s.replace(/^DNS:/, '').trim().toLowerCase());
  const hostLow = hostname.toLowerCase();
  for (const s of sans) {
    if (s === hostLow) return { match: true, detail: `SAN match: ${s}` };
    if (s.startsWith('*.')) {
      const base = s.slice(2);
      if (hostLow.endsWith('.' + base) || hostLow === base) return { match: true, detail: `Wildcard SAN match: ${s}` };
    }
  }

  return {
    match: false,
    detail: `MISMATCH — hostname: ${hostname}, cert CN: ${cn}, SANs: ${sans.slice(0,3).join(', ')}`
  };
}

function categoriseSubdomain(label) {
  const l = label.toLowerCase();
  if (HOSTING_DEFAULT_NAMES.includes(l)) return 'hosting-default';
  if (/^dev[.\-_]|[.\-_]dev$|^dev$/i.test(l)) return 'development';
  if (/^stag|^staging|^test|^qa\b/i.test(l)) return 'non-production';
  if (/^portal|^hub|^gateway|^ui|^app/i.test(l)) return 'internal-platform';
  if (/^remote|^vpn|^apollo|^jump/i.test(l)) return 'remote-access';
  if (/^grafana|^kibana|^prometheus|^monitor/i.test(l)) return 'monitoring';
  if (/^mail|^email|^smtp|^mx|^webmail/i.test(l)) return 'mail';
  return 'other';
}

// ─── Core TLS Probe ───────────────────────────────────────────────────────────

async function probeTLS(hostname, options = {}) {
  const {
    port = TLS_PORT,
    timeoutMs = CONNECT_TIMEOUT_MS,
    tlsVersion = null,   // force specific version
    ciphers = null,
    pinnedIP = null,     // IP-pin to prevent DNS rebinding; if set, connect to this IP
  } = options;

  return new Promise((resolve) => {
    const connectOptions = {
      host: pinnedIP || hostname,  // connect to pinned IP if provided
      port,
      servername: hostname,        // SNI always uses the original hostname
      rejectUnauthorized: false,
      ecdhCurve: 'X25519:P-256:P-384:P-521',
    };

    if (tlsVersion) {
      connectOptions.minVersion = tlsVersion;
      connectOptions.maxVersion = tlsVersion;
    }

    if (ciphers) {
      connectOptions.ciphers = ciphers;
    }

    let resolved = false;
    const done = (result) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };

    // Hard wall-clock timeout independent of socket inactivity.
    // socket.setTimeout only fires on *inactivity* — a server dripping bytes
    // can stall a probe indefinitely. This timer always fires at timeoutMs.
    const wallTimer = setTimeout(() => {
      if (socket) try { socket.destroy(); } catch {}
      done({ reachable: false, error: 'Hard timeout', errorCode: 'ETIMEOUT_HARD' });
    }, timeoutMs + 500);

    let socket;
    try {
      socket = tls.connect(connectOptions, () => {
        clearTimeout(wallTimer);
        try {
          const cert    = socket.getPeerCertificate(true);
          const cipher  = socket.getCipher();
          const protocol = socket.getProtocol();
          const alpn    = socket.alpnProtocol;

          // Capture raw DER bytes for accurate signature algorithm detection.
          // cert.raw is a Buffer available in Node 15+.
          const rawDER = cert.raw || null;

          done({
            reachable: true,
            protocol,
            cipher,
            alpn: alpn || null,
            cert: {
              subject:        cert.subject,
              issuer:         cert.issuer,
              subjectaltname: cert.subjectaltname,
              valid_from:     cert.valid_from,
              valid_to:       cert.valid_to,
              bits:           cert.bits,
              exponent:       cert.exponent,
              fingerprint256: cert.fingerprint256,
              serialNumber:   cert.serialNumber,
              ca:             cert.ca,
              ext_key_usage:  cert.ext_key_usage,
              _raw:           rawDER,   // kept for DER sig-alg parsing; not serialised to JSON
            },
            error: null,
          });
        } catch (e) {
          done({ reachable: true, error: e.message });
        } finally {
          socket.destroy();
        }
      });

      socket.on('error', (e) => {
        clearTimeout(wallTimer);
        done({ reachable: false, error: e.message, errorCode: e.code });
      });

      socket.setTimeout(timeoutMs, () => {
        clearTimeout(wallTimer);
        socket.destroy();
        done({ reachable: false, error: 'Connection timeout', errorCode: 'ETIMEDOUT' });
      });
    } catch (e) {
      clearTimeout(wallTimer);
      done({ reachable: false, error: e.message });
    }
  });
}

// ─── DNS Probe ────────────────────────────────────────────────────────────────

async function probeDNS(hostname) {
  const result = {
    resolvesA: false, resolvesAAAA: false,
    aRecords: [], aaaaRecords: [],
    mxRecords: [], nsRecords: [], txtRecords: [],
    cnameTarget: null, error: null,
  };

  // Wrap each DNS query in a 4s timeout — some queries (MX, TXT on dead names)
  // can stall for 30s+ without a hard limit
  const withTimeout = (p, ms = 4000) =>
    Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error('DNS timeout')), ms))]);

  const tasks = [
    withTimeout(dns.resolve4(hostname)).then(r => { result.resolvesA = true; result.aRecords = r; }).catch(() => {}),
    withTimeout(dns.resolve6(hostname)).then(r => { result.resolvesAAAA = true; result.aaaaRecords = r; }).catch(() => {}),
    withTimeout(dns.resolveCname(hostname)).then(r => { result.cnameTarget = r[0] || null; }).catch(() => {}),
    withTimeout(dns.resolveMx(hostname)).then(r => { result.mxRecords = r; }).catch(() => {}),
    withTimeout(dns.resolveNs(hostname)).then(r => { result.nsRecords = r; }).catch(() => {}),
    withTimeout(dns.resolveTxt(hostname)).then(r => { result.txtRecords = r.flat(); }).catch(() => {}),
  ];

  await Promise.allSettled(tasks);
  result.resolves = result.resolvesA || result.resolvesAAAA || result.cnameTarget !== null;
  return result;
}

// ─── Legacy TLS Version Probes ────────────────────────────────────────────────

async function probeLegacyTLS(hostname) {
  const versions = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1'];
  // Run all version probes in parallel rather than sequentially
  const probes = await Promise.all(
    versions.map(ver =>
      probeTLS(hostname, { tlsVersion: ver, timeoutMs: 4000 })
        .then(probe => [ver, {
          supported: probe.reachable && !probe.error,
          cipher: probe.cipher?.name || null,
          error: probe.error || null,
        }])
        .catch(() => [ver, { supported: false, cipher: null, error: 'probe failed' }])
    )
  );
  return Object.fromEntries(probes);
}

// ─── Weak Cipher Probe ────────────────────────────────────────────────────────

// Markers that indicate a genuinely weak cipher was negotiated
const WEAK_CIPHER_MARKERS = ['RC4', 'NULL', 'EXPORT', 'EXP-', '_DES_', 'ADH-', 'AECDH-'];

function isWeakCipherName(name) {
  if (!name) return false;
  const upper = name.toUpperCase();
  return WEAK_CIPHER_MARKERS.some(m => upper.includes(m));
}

async function probeWeakCiphers(hostname) {
  const weakCipherSuites = [
    'RC4-SHA', 'RC4-MD5', 'DES-CBC3-SHA', 'DES-CBC-SHA',
    'EXP-RC4-MD5', 'EXP-DES-CBC-SHA', 'NULL-SHA', 'NULL-MD5',
    'ECDHE-RSA-RC4-SHA', 'ADH-AES128-SHA',
  ].join(':');

  const probe = await probeTLS(hostname, {
    ciphers: weakCipherSuites,
    timeoutMs: 5000,
  });

  // A TLS proxy or modern server may accept the connection but negotiate a
  // strong cipher regardless of our preference list. We only flag it if the
  // actual negotiated cipher is genuinely weak.
  const negotiated = probe.cipher?.name || probe.cipher?.standardName || null;
  const weakAccepted = probe.reachable && !probe.error && isWeakCipherName(negotiated);

  return {
    weakCipherAccepted: weakAccepted,
    negotiatedWeakCipher: weakAccepted ? negotiated : null,
    note: (!weakAccepted && probe.reachable)
      ? `Connection succeeded but negotiated ${negotiated} — not weak`
      : null,
  };
}

// ─── HSTS Probe (HTTP redirect + header) ─────────────────────────────────────

async function probeHTTPS(hostname) {
  return new Promise((resolve) => {
    const http = require('http');
    const options = { host: hostname, port: 80, path: '/', method: 'HEAD', timeout: 3000 };
    const req = http.request(options, (res) => {
      resolve({
        httpReachable: true,
        redirectsToHTTPS: (res.headers.location || '').startsWith('https://'),
        statusCode: res.statusCode,
        location: res.headers.location || null,
      });
    });
    req.on('error', () => resolve({ httpReachable: false }));
    req.setTimeout(3000, () => { req.destroy(); resolve({ httpReachable: false }); });
    req.end();
  });
}

// ─── Full Host Analysis ───────────────────────────────────────────────────────

async function analyseHost(hostname, opts = {}) {
  const {
    deepLegacyProbe = true,
    weakCipherProbe = true,
    pinnedIP = null,     // resolved public IP — prevents DNS rebinding at connect time
  } = opts;

  // 1. DNS
  const dnsResult = await probeDNS(hostname);

  // 2. Skip TLS probe immediately if DNS doesn't resolve.
  //    This is the single biggest performance win: ~70% of wordlist entries are
  //    NXDOMAIN and each previously burned the full 5s TCP connect timeout.
  if (!dnsResult.resolves) {
    return {
      hostname,
      timestamp: new Date().toISOString(),
      dns: dnsResult,
      tls: null,
      findings: [{
        id: 'DNS-NXDOMAIN', severity: 'info', area: 'dns',
        title: 'Host does not resolve in DNS',
        detail: `${hostname} returned NXDOMAIN or no A/AAAA/CNAME record.`,
      }],
      riskScore:    0,
      pqReadiness:  'not-applicable',
      hndlRisk:     'not-applicable',
      tnflRisk:     'not-applicable',
    };
  }

  // 3. Primary TLS probe (connect to pinned IP to prevent DNS-rebinding)
  const tlsResult = await probeTLS(hostname, { pinnedIP: pinnedIP || dnsResult.aRecords?.[0] || null });

  const result = {
    hostname,
    timestamp: new Date().toISOString(),
    dns: dnsResult,
    tls: null,
    findings: [],
    riskScore: 0,   // 0-100
    pqReadiness: 'unknown', // none | partial | ready
    hndlRisk: 'unknown',
    tnflRisk: 'unknown',
  };

  // DNS surface findings
  const label = hostname.split('.')[0];
  const subCat = categoriseSubdomain(label);

  // DNS-NXDOMAIN is handled above (early return); we only reach here when resolves=true.
  if (subCat === 'hosting-default') {
    result.findings.push({
      id: 'DNS-HOSTING-DEFAULT',
      severity: 'medium',
      area: 'dns',
      title: 'Hosting-platform default subdomain in public DNS',
      detail: `'${label}' matches a cPanel/hosting-default naming pattern. If this record is vestigial, it discloses the hosting platform and expands the attack surface unnecessarily.`,
      recommendation: 'Audit whether this record points to a live service. Remove if not required.',
    });
  } else if (subCat === 'development') {
    result.findings.push({
      id: 'DNS-DEV-EXPOSED',
      severity: 'high',
      area: 'dev-infrastructure',
      title: 'Development subdomain in public DNS',
      detail: `'${hostname}' appears to be a development environment (matching pattern: dev*). Development infrastructure exposed to the public internet typically runs unpatched software, verbose error pages, and may hold copies of production data without production-grade controls.`,
      recommendation: 'Place behind authenticated proxy or IP allowlist, or remove from public DNS.',
      priority: 'P1',
    });
  } else if (subCat === 'monitoring') {
    result.findings.push({
      id: 'DNS-MONITORING-EXPOSED',
      severity: 'high',
      area: 'dns',
      title: 'Monitoring infrastructure in public DNS',
      detail: `'${hostname}' appears to be monitoring infrastructure (Grafana, Kibana etc.) publicly reachable. Monitoring dashboards often expose internal topology and credentials.`,
      recommendation: 'Restrict to VPN / private network. Remove from public DNS.',
      priority: 'P1',
    });
  } else if (subCat === 'internal-platform') {
    result.findings.push({
      id: 'DNS-INTERNAL-PLATFORM',
      severity: 'medium',
      area: 'dns',
      title: 'Internal platform component in public DNS',
      detail: `'${hostname}' appears to be an internal platform component (portal, hub, gateway). Its presence in public DNS reveals internal architecture to anyone running subdomain enumeration.`,
      recommendation: 'Use split-horizon DNS or a private DNS zone. Remove from public DNS if not intended to be externally reachable.',
    });
  } else if (subCat === 'remote-access') {
    result.findings.push({
      id: 'DNS-REMOTE-ACCESS',
      severity: 'medium',
      area: 'dns',
      title: 'Remote access service in public DNS',
      detail: `'${hostname}' appears to be a remote access or VPN endpoint. Public DNS disclosure enables targeted attacks on remote access infrastructure.`,
      recommendation: 'Verify whether external reachability is required. Document the rationale.',
    });
  }

  if (!tlsResult.reachable) {
    // DNS resolves but TLS failed
    if (dnsResult.resolves) {
      result.findings.push({
        id: 'TLS-UNREACHABLE',
        severity: 'info',
        area: 'dns',
        title: 'Host resolves in DNS but did not complete TLS handshake',
        detail: `${hostname} has DNS records but TCP/443 did not yield a completed TLS handshake (${tlsResult.error || 'unknown error'}). This pattern is consistent with internally-scoped or dormant infrastructure advertised in public DNS.`,
        recommendation: 'Determine if this host should be publicly reachable. If not, remove the DNS record.',
      });
      result.riskScore += 5;
    }
    result.hndlRisk = 'not-applicable';
    result.tnflRisk = 'not-applicable';
    result.pqReadiness = 'not-applicable';
    return result;
  }

  // ─── TLS is reachable ────────────────────────────────────────────────────

  const { protocol, cipher, cert } = tlsResult;

  result.tls = {
    protocol,
    cipher: cipher?.name,
    cipherStandardName: cipher?.standardName,
  };

  // Protocol version findings
  const versionRisk = TLS_VERSION_RISK[protocol];
  if (versionRisk) {
    if (versionRisk.risk === 'critical') {
      result.findings.push({
        id: 'TLS-DEPRECATED-PROTOCOL',
        severity: 'critical',
        area: 'tls-protocol',
        title: `Deprecated TLS version in use: ${versionRisk.label}`,
        detail: `Server negotiated ${protocol}, which is deprecated under RFC 8996. This exposes connections to known downgrade and decryption attacks (BEAST, POODLE, CRIME).`,
        recommendation: 'Disable TLS 1.0 and TLS 1.1 immediately. Require TLS 1.2 as minimum; prefer TLS 1.3.',
        priority: 'P1',
      });
      result.riskScore += 40;
    } else if (versionRisk.risk === 'low') {
      result.findings.push({
        id: 'TLS-VERSION-1.2',
        severity: 'low',
        area: 'tls-protocol',
        title: 'TLS 1.2 in use (TLS 1.3 preferred)',
        detail: 'Server negotiated TLS 1.2. While not deprecated, TLS 1.3 provides stronger security guarantees and better performance.',
        recommendation: 'Prefer TLS 1.3 where the client stack supports it.',
      });
      result.riskScore += 5;
    }
  }

  // KEX analysis
  const kexAnalysis = classifyKex(cipher?.standardName || cipher?.name, protocol);
  result.tls.kex = kexAnalysis;

  if (kexAnalysis.pqStatus === 'classical') {
    result.findings.push({
      id: 'KEX-CLASSICAL',
      severity: 'high',
      area: 'tls-kex',
      title: 'Classical (quantum-vulnerable) key exchange in use',
      detail: `TLS 1.2 cipher suite encodes ${kexAnalysis.label}. This key exchange is vulnerable to Shor's algorithm on a Cryptanalytically-Relevant Quantum Computer (CRQC). Any session traffic recorded today (Harvest-Now-Decrypt-Later) can be decrypted once a CRQC exists.`,
      recommendation: 'Upgrade to TLS 1.3 with X25519MLKEM768 hybrid key exchange (OpenSSL 3.5+, Go 1.24+).',
      priority: 'P1',
      nistRef: 'SC-8, SC-12, SC-23 | NIST IR 8547 | draft-ietf-tls-ecdhe-mlkem-05',
    });
    result.riskScore += 35;
    result.hndlRisk = 'high';
    result.pqReadiness = 'none';
  } else if (kexAnalysis.pqStatus === 'classical-likely') {
    // TLS 1.3 — KEX group not determinable from standard API
    result.findings.push({
      id: 'KEX-PQ-STATUS-UNKNOWN',
      severity: 'medium',
      area: 'tls-kex',
      title: 'Post-quantum KEX status requires deep enumeration',
      detail: `Server negotiated TLS 1.3. The TLS 1.3 key exchange group (X25519, P-256, or hybrid PQ X25519MLKEM768) cannot be determined from standard TLS socket API — it requires a deep enumeration tool (testssl.sh, sslyze, or equivalent) that negotiates and reports the supported named groups. Based on mid-2026 industry baseline, classical X25519 without hybrid PQ is the most likely state; hybrid PQ KEX (X25519MLKEM768) requires explicit server-side enablement in OpenSSL 3.5+.`,
      recommendation: 'Run a deep TLS enumeration (testssl.sh --groups) to confirm KEX group. If X25519MLKEM768 is not listed, enable it and prioritise it.',
      priority: 'P1',
      nistRef: 'SC-8, SC-12 | NIST IR 8547 | draft-ietf-tls-ecdhe-mlkem-05',
    });
    result.riskScore += 20;
    result.hndlRisk = 'high-likely'; // most probable state for 2026 infrastructure
    result.pqReadiness = 'unknown';
  } else if (kexAnalysis.pqStatus === 'pq-hybrid' || kexAnalysis.pqStatus === 'pq') {
    result.findings.push({
      id: 'KEX-PQ-DETECTED',
      severity: 'info',
      area: 'tls-kex',
      title: 'Post-quantum or hybrid PQ key exchange detected',
      detail: `Server negotiated ${kexAnalysis.label}. Session key exchange is quantum-resistant. HNDL risk on key exchange is mitigated.`,
    });
    result.riskScore += 0;
    result.hndlRisk = 'mitigated';
    result.pqReadiness = 'partial'; // still need PQ certs
  }

  // Symmetric cipher
  const cipherName = cipher?.standardName || cipher?.name || '';
  const symmetricOk = SAFE_SYMMETRIC.some(s => cipherName.includes(s));
  if (!symmetricOk && cipherName) {
    result.findings.push({
      id: 'CIPHER-WEAK-SYMMETRIC',
      severity: 'medium',
      area: 'tls-cipher',
      title: `Symmetric cipher may be insufficient: ${cipherName}`,
      detail: 'AES-256-GCM, AES-256-CCM, or ChaCha20-Poly1305 are recommended. 128-bit key ciphers may be reduced to ~64-bit effective security under Grover\'s algorithm, though this is not an immediate practical threat.',
      recommendation: 'Prefer AES-256-GCM or ChaCha20-Poly1305 cipher suites.',
    });
    result.riskScore += 10;
  }

  // Certificate analysis
  if (cert) {
    const sigClass = classifyCertSig(cert);
    result.tls.certSig = sigClass;

    // Is the cert PQ-signed?
    if (sigClass.pqStatus === 'quantum-vulnerable') {
      result.findings.push({
        id: 'CERT-CLASSICAL-SIG',
        severity: 'medium',
        area: 'certificate',
        title: 'Certificate uses classical (quantum-vulnerable) signature algorithm',
        detail: `Certificate signature algorithm: ${sigClass.algorithm}. RSA and ECDSA signatures are vulnerable to Shor's algorithm (Trust-Now-Forge-Later: a CRQC could derive the CA's private key and forge certificates for this domain).`,
        recommendation: 'Adopt ML-DSA (FIPS 204) leaf certificates when your CA offers them (expected 2027+). Track CA/Browser Forum activity.',
        priority: 'P2',
        nistRef: 'SC-12, SC-13, SC-17 | NIST FIPS 204 | NIST IR 8547',
      });
      result.riskScore += 15;
      result.tnflRisk = 'high';
    } else if (sigClass.pqStatus === 'quantum-safe') {
      result.tnflRisk = 'mitigated';
    }

    // Certificate expiry
    const daysLeft = daysUntil(cert.valid_to);
    if (daysLeft !== null) {
      result.tls.certDaysToExpiry = daysLeft;
      if (daysLeft < 0) {
        result.findings.push({
          id: 'CERT-EXPIRED',
          severity: 'critical',
          area: 'certificate',
          title: 'Certificate is EXPIRED',
          detail: `Certificate expired ${Math.abs(daysLeft)} day(s) ago (${cert.valid_to}). Connections will be rejected by browsers.`,
          recommendation: 'Renew immediately.',
          priority: 'P1',
        });
        result.riskScore += 50;
      } else if (daysLeft < 14) {
        result.findings.push({
          id: 'CERT-EXPIRY-CRITICAL',
          severity: 'high',
          area: 'certificate',
          title: `Certificate expires in ${daysLeft} days`,
          detail: `Critical expiry window. Certificate expires: ${cert.valid_to}.`,
          recommendation: 'Renew immediately.',
          priority: 'P1',
        });
        result.riskScore += 20;
      } else if (daysLeft < 30) {
        result.findings.push({
          id: 'CERT-EXPIRY-WARNING',
          severity: 'medium',
          area: 'certificate',
          title: `Certificate expires in ${daysLeft} days`,
          detail: `Certificate expires: ${cert.valid_to}. Short window — initiate renewal.`,
          recommendation: 'Renew within the next two weeks.',
        });
        result.riskScore += 10;
      }
    }

    // CA posture — classical vs. PQ-capable
    const issuerO = cert.issuer?.O || '';
    const issuerCN = cert.issuer?.CN || '';
    result.tls.caName = issuerO || issuerCN;
    result.tls.caClassical = isCAClassical(issuerO, issuerCN);

    // SNI matching
    const sniResult = sniMatch(hostname, cert.subject, cert.subjectaltname);
    result.tls.sniMatch = sniResult;
    if (!sniResult.match) {
      result.findings.push({
        id: 'SNI-MISMATCH',
        severity: 'high',
        area: 'sni',
        title: 'SNI / certificate mismatch',
        detail: `${sniResult.detail}. This typically indicates a misconfigured CDN back-end, an incomplete custom-hostname binding, or an unintended fall-through to a hosting provider's catch-all certificate. It produces browser security warnings and undermines the trust signal at first contact.`,
        recommendation: 'Bind a valid certificate matching the queried hostname, or remove the subdomain from public DNS if it should not be reachable.',
        priority: 'P1',
        nistRef: 'CM-3, CM-5, SC-17 | PR.PS-01',
      });
      result.riskScore += 25;
    }
  }

  // Legacy TLS probe (optional, takes extra time)
  if (deepLegacyProbe) {
    const legacyResults = await probeLegacyTLS(hostname);
    result.tls.legacyVersionSupport = legacyResults;

    for (const [ver, res] of Object.entries(legacyResults)) {
      if (res.supported && TLS_VERSION_RISK[ver]?.risk === 'critical') {
        result.findings.push({
          id: `TLS-LEGACY-${ver.replace('.', '-')}`,
          severity: 'critical',
          area: 'tls-protocol',
          title: `Legacy ${ver} accepted`,
          detail: `Server accepts ${ver} connections. ${TLS_VERSION_RISK[ver].label}.`,
          recommendation: `Disable ${ver} in server TLS configuration immediately.`,
          priority: 'P1',
        });
        result.riskScore += 30;
      }
    }
  }

  // Weak cipher probe
  if (weakCipherProbe) {
    const weakResult = await probeWeakCiphers(hostname);
    result.tls.weakCipherTest = weakResult;
    if (weakResult.weakCipherAccepted) {
      result.findings.push({
        id: 'CIPHER-WEAK-ACCEPTED',
        severity: 'critical',
        area: 'tls-cipher',
        title: `Weak cipher suite accepted: ${weakResult.negotiatedWeakCipher}`,
        detail: 'Server accepted a known-weak cipher suite (RC4, NULL, EXPORT, or 3DES). These ciphers are broken and provide no meaningful confidentiality.',
        recommendation: 'Remove all weak cipher suites from the server configuration immediately.',
        priority: 'P1',
      });
      result.riskScore += 40;
    }
  }

  // HTTP HSTS check
  const httpResult = await probeHTTPS(hostname);
  result.tls.httpReachable = httpResult.httpReachable;
  if (httpResult.httpReachable && !httpResult.redirectsToHTTPS) {
    result.findings.push({
      id: 'HTTP-NO-REDIRECT',
      severity: 'medium',
      area: 'tls-enforcement',
      title: 'HTTP port reachable but does not redirect to HTTPS',
      detail: 'TCP/80 is reachable and does not issue a redirect to HTTPS. This permits plaintext HTTP connections.',
      recommendation: 'Issue a 301 redirect from HTTP to HTTPS. Enable HSTS (Strict-Transport-Security) with a long max-age.',
    });
    result.riskScore += 15;
  }

  // ─── Final PQ readiness determination ────────────────────────────────────

  if (result.hndlRisk === 'mitigated' && result.tnflRisk === 'mitigated') {
    result.pqReadiness = 'ready';
  } else if (result.hndlRisk === 'mitigated' || result.tnflRisk === 'mitigated') {
    result.pqReadiness = 'partial';
  } else if (result.hndlRisk === 'high' || result.hndlRisk === 'high-likely') {
    result.pqReadiness = 'none';
  }

  result.riskScore = Math.min(100, result.riskScore);

  return result;
}

// ─── Domain Scanner ───────────────────────────────────────────────────────────

// ─── Expanded subdomain wordlist ─────────────────────────────────────────────
// ~500 high-value names drawn from real-world enumeration datasets.
// Ordered by probability of existence; CT log discovery supplements this.
const SUBDOMAIN_WORDLIST = [
  // Apex + www
  '', 'www', 'www2', 'www3',

  // Mail / messaging
  'mail', 'mail1', 'mail2', 'email', 'webmail', 'smtp', 'smtp1', 'smtp2',
  'pop', 'pop3', 'imap', 'mx', 'mx1', 'mx2', 'mx3', 'exchange',
  'autodiscover', 'autoconfig', 'relay', 'bounce', 'lists', 'mailgun',
  'sendgrid', 'ses', 'postfix', 'mailhog',

  // Auth / identity
  'auth', 'sso', 'login', 'signin', 'logout', 'oauth', 'id', 'identity',
  'adfs', 'okta', 'ping', 'saml', 'sts', 'idp', 'token', 'accounts',
  'account', 'register', 'signup', 'password', 'reset', 'mfa', 'otp',

  // APIs
  'api', 'api2', 'api3', 'apis', 'api-v1', 'api-v2', 'api-v3',
  'rest', 'graphql', 'grpc', 'rpc', 'gateway', 'apigw', 'api-gateway',
  'integration', 'integrations', 'webhook', 'webhooks', 'socket', 'ws',
  'public-api', 'private-api', 'internal-api', 'external-api',

  // CDN / static
  'cdn', 'cdn1', 'cdn2', 'static', 'static1', 'static2', 'assets',
  'media', 'img', 'images', 'image', 'video', 'videos', 'audio',
  'files', 'file', 'uploads', 'upload', 'downloads', 'download',
  'resources', 'content', 'data', 'cache', 's3', 'storage', 'blob',

  // Apps / portals
  'app', 'apps', 'app1', 'app2', 'application', 'applications',
  'portal', 'hub', 'dashboard', 'console', 'control', 'panel',
  'admin', 'admin1', 'administrator', 'manage', 'management',
  'client', 'clients', 'customer', 'customers', 'partner', 'partners',
  'member', 'members', 'user', 'users', 'profile', 'profiles',
  'secure', 'protected', 'private', 'restricted',

  // Development / test environments
  'dev', 'dev1', 'dev2', 'development', 'develop',
  'staging', 'stage', 'stg', 'stg1', 'stg2',
  'test', 'test1', 'test2', 'testing', 'tst',
  'qa', 'qa1', 'qa2', 'quality',
  'uat', 'uat1', 'uat2', 'acceptance',
  'sandbox', 'sbx', 'preview', 'pre', 'preprod', 'pre-prod',
  'demo', 'demo1', 'demo2', 'beta', 'alpha', 'canary',
  'local', 'localhost', 'internal', 'int', 'int1',
  'rc', 'release', 'hotfix', 'feature', 'experimental',

  // Infrastructure / DevOps
  'vpn', 'vpn1', 'vpn2', 'remote', 'rdp', 'citrix', 'juniper',
  'pulse', 'globalprotect', 'anyconnect', 'openvpn', 'wireguard',
  'ssh', 'jump', 'bastion', 'proxy', 'proxy1', 'proxy2',
  'firewall', 'fw', 'lb', 'loadbalancer', 'haproxy', 'nginx',
  'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
  'ntp', 'time', 'radius', 'ldap', 'ad', 'dc', 'dc1', 'dc2',

  // Monitoring / observability
  'monitor', 'monitoring', 'grafana', 'kibana', 'prometheus',
  'alertmanager', 'alert', 'alerts', 'opsgenie', 'pagerduty',
  'nagios', 'zabbix', 'datadog', 'newrelic', 'splunk',
  'elk', 'elastic', 'elasticsearch', 'logstash', 'fluentd',
  'metrics', 'logs', 'log', 'apm', 'trace', 'tracing', 'healthcheck',
  'health', 'status', 'uptime', 'ping',

  // CI/CD / source control
  'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'repos',
  'registry', 'docker', 'harbor', 'nexus', 'artifactory',
  'jenkins', 'ci', 'cd', 'cicd', 'build', 'builds', 'pipeline',
  'drone', 'travis', 'circle', 'argocd', 'flux', 'helm',

  // Cloud / kubernetes
  'k8s', 'kubernetes', 'rancher', 'openshift', 'nomad',
  'vault', 'consul', 'terraform', 'ansible',
  'aws', 'azure', 'gcp', 'cloud', 'cluster', 'node',

  // Collaboration / productivity
  'jira', 'confluence', 'wiki', 'wiki1', 'docs', 'doc', 'documentation',
  'sharepoint', 'teams', 'slack', 'meet', 'video', 'conference',
  'calendar', 'cal', 'hr', 'hris', 'erp', 'crm', 'salesforce',
  'workday', 'sap', 'oracle', 'netsuite', 'servicenow',

  // Finance / payments
  'billing', 'bill', 'invoice', 'invoices', 'pay', 'payment', 'payments',
  'checkout', 'cart', 'shop', 'store', 'ecommerce', 'commerce',
  'stripe', 'paypal', 'finance', 'accounting', 'accounts-payable',
  'treasury', 'bank', 'transaction',

  // Hosting defaults (cPanel / Plesk)
  'webdisk', 'cpanel', 'whm', 'plesk', 'ftp', 'sftp',
  'webmail', 'autodiscover', 'autoconfig',

  // Marketing / web
  'blog', 'news', 'press', 'media-room', 'newsroom',
  'marketing', 'promo', 'campaign', 'campaigns', 'landing',
  'careers', 'jobs', 'recruit', 'recruitment',
  'help', 'support', 'helpdesk', 'servicedesk', 'ticket', 'tickets',
  'feedback', 'survey', 'forms', 'form',
  'tracking', 'track', 'click', 'open', 'pixel',

  // Mobile / versioned
  'm', 'mobile', 'wap', 'pwa', 'native',
  'v1', 'v2', 'v3', 'v4', 'new', 'old', 'legacy', 'classic',
  'next', 'preview2', 'future',

  // Security-specific
  'siem', 'soc', 'threat', 'pentest', 'scan', 'vulnerability',
  'cert', 'certs', 'pki', 'ca', 'crl', 'ocsp', 'acme',

  // Misc common
  'intranet', 'extranet', 'corpnet', 'corp',
  'connect', 'relay', 'edge', 'origin', 'backend', 'frontend',
  'web', 'web1', 'web2', 'server', 'server1', 'server2',
  'host', 'host1', 'host2', 'node1', 'node2',
  'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'memcache',
  'backup', 'backups', 'archive', 'archives', 'dr', 'disaster',
  'prod', 'production', 'live', 'preprod',
];

async function generateSubdomains(domain) {
  return SUBDOMAIN_WORDLIST.map(sub => sub ? `${sub}.${domain}` : domain);
}

// ─── Certificate Transparency log discovery ───────────────────────────────────
// Queries crt.sh to find all subdomains that have ever had a certificate issued.
// This reveals the real external footprint independent of DNS guessing.
async function discoverViaCT(domain) {
  return new Promise((resolve) => {
    const https = require('https');
    const options = {
      hostname: 'crt.sh',
      path: `/?q=%.${encodeURIComponent(domain)}&output=json`,
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'CipherQ-PQC-Scanner/1.0',
      },
      timeout: 15000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) {
            return resolve({ hosts: [], source: 'ct-log', error: `HTTP ${res.statusCode}` });
          }
          const entries = JSON.parse(data);
          const names = new Set();

          for (const entry of entries) {
            // name_value may contain multiple names newline-separated
            const rawNames = (entry.name_value || '').split('\n');
            for (const name of rawNames) {
              const n = name.trim().toLowerCase().replace(/^\*\./, '');
              // Only include direct subdomains of the target domain
              if (n.endsWith(`.${domain}`) || n === domain) {
                // Exclude wildcard entries themselves
                if (!n.startsWith('*')) names.add(n);
              }
            }
          }

          resolve({
            hosts: [...names].sort(),
            source: 'ct-log',
            totalCerts: entries.length,
            error: null,
          });
        } catch (e) {
          resolve({ hosts: [], source: 'ct-log', error: e.message });
        }
      });
    });

    req.on('error', (e) => {
      resolve({ hosts: [], source: 'ct-log', error: e.message });
    });

    req.setTimeout(15000, () => {
      req.destroy();
      resolve({ hosts: [], source: 'ct-log', error: 'CT log query timed out' });
    });

    req.end();
  });
}

async function scanDomain(domain, opts = {}) {
  const {
    customHosts = [],
    ctHostsFromBrowser = [],
    concurrency = 8,
    deepLegacyProbe = true,
    weakCipherProbe = true,
    onProgress = null,
    useCTLog = false,  // server-side CT disabled; browser handles it
  } = opts;

  let hosts;
  let ctResult = null;

  if (customHosts.length > 0 && ctHostsFromBrowser.length === 0) {
    // Explicit custom list with no CT supplement — use as-is
    hosts = [...new Set(customHosts)];
  } else {
    // Always start with the full wordlist
    const wordlistHosts = await generateSubdomains(domain);

    if (ctHostsFromBrowser.length > 0) {
      // Merge browser-discovered CT hosts with wordlist
      const merged = new Set([...wordlistHosts, ...ctHostsFromBrowser]);
      hosts = [...merged];
      ctResult = {
        hosts: ctHostsFromBrowser,
        source: 'browser',
        error: null,
      };
    } else if (useCTLog) {
      // Server-side CT (only used when running locally or egress is open)
      if (onProgress) onProgress({ phase: 'ct-discovery', completed: 0, total: 0, message: 'Querying Certificate Transparency logs…' });
      ctResult = await discoverViaCT(domain);
      const merged = new Set([...wordlistHosts, ...(ctResult.hosts || [])]);
      hosts = [...merged];
    } else {
      hosts = wordlistHosts;
    }
  }

  const results = new Array(hosts.length);
  let completed = 0;

  // Hard per-host timeout — prevents DNS stalls and TCP black-holes from
  // blocking the entire scan. NXDOMAIN early-exit in analyseHost means most
  // hosts bail out in <50ms; this 12s ceiling covers the long tail.
  const analyseWithTimeout = (host) =>
    Promise.race([
      analyseHost(host, { deepLegacyProbe, weakCipherProbe }),
      new Promise(resolve => setTimeout(() => resolve({
        hostname: host,
        timestamp: new Date().toISOString(),
        dns: { resolves: false, aRecords: [] },
        tls: null,
        findings: [],
        riskScore: 0,
        pqReadiness: 'not-applicable',
        hndlRisk: 'not-applicable',
        tnflRisk: 'not-applicable',
        _timedOut: true,
      }), 12000)),
    ]);

  // Pull-based worker pool — each worker grabs the next host the instant it
  // finishes, keeping all concurrency lanes saturated. Fixed-batch Promise.all
  // stalls each batch on its slowest host; this avoids that.
  let nextIdx = 0;
  async function worker() {
    while (true) {
      const idx = nextIdx++;
      if (idx >= hosts.length) return;
      const result = await analyseWithTimeout(hosts[idx]);
      results[idx] = result;
      completed++;
      if (onProgress) onProgress({ completed, total: hosts.length, latest: [result] });
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));

  // Summarise
  const reachable = results.filter(r => r.tls?.cipher);
  const unreachable = results.filter(r => !r.tls?.cipher && r.dns?.resolves);
  const nxdomain = results.filter(r => !r.dns?.resolves);

  const allFindings = results.flatMap(r => r.findings.map(f => ({ ...f, hostname: r.hostname })));

  const summary = {
    domain,
    scanTime: new Date().toISOString(),
    hostsProbed: hosts.length,
    hostsReachable: reachable.length,
    hostsUnreachable: unreachable.length,
    hostsNxdomain: nxdomain.length,
    findingsTotal: allFindings.length,
    ctLog: ctResult ? {
      enabled: true,
      hostsDiscovered: ctResult.hosts.length,
      totalCerts: ctResult.totalCerts || 0,
      error: ctResult.error,
    } : { enabled: false },
    findingsBySeverity: {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length,
    },
    pqReadinessBreakdown: {
      none: reachable.filter(r => r.pqReadiness === 'none').length,
      unknown: reachable.filter(r => r.pqReadiness === 'unknown').length,
      partial: reachable.filter(r => r.pqReadiness === 'partial').length,
      ready: reachable.filter(r => r.pqReadiness === 'ready').length,
    },
    protocolsObserved: [...new Set(reachable.map(r => r.tls.protocol))],
    ciphersObserved: [...new Set(reachable.map(r => r.tls.cipher).filter(Boolean))],
    casObserved: [...new Set(reachable.map(r => r.tls.caName).filter(Boolean))],
    sniMismatches: reachable.filter(r => r.tls?.sniMatch && !r.tls.sniMatch.match).map(r => r.hostname),
    devHostsExposed: results.filter(r => r.findings.some(f => f.id === 'DNS-DEV-EXPOSED')).map(r => r.hostname),
    overallHndlRisk: reachable.some(r => r.hndlRisk === 'high') ? 'high' :
                      reachable.some(r => r.hndlRisk === 'high-likely') ? 'high-likely' :
                      reachable.some(r => r.hndlRisk === 'mitigated') ? 'partial' : 'unknown',
  };

  return { summary, hosts: results, findings: allFindings };
}

module.exports = {
  analyseHost,
  scanDomain,
  probeTLS,
  probeDNS,
  generateSubdomains,
  discoverViaCT,
  categoriseSubdomain,
};
