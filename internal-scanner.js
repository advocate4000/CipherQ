'use strict';

/**
 * CipherQ — Internal Discovery Scanner
 *
 * Code / SCA scan:  walks a source tree looking for crypto API usage,
 *                   hardcoded secrets, pinned vulnerable libraries,
 *                   and OpenSSL/Go/BoringSSL version indicators
 *
 * PKI scan:         parses PEM/DER certificate files found in a directory
 *                   tree and checks for classical/expired/near-expiry certs
 *
 * Runs on the local filesystem the server process can read.
 * On Render this is the instance's own tree; on self-hosted it points at
 * the customer's checkout path.
 */

const fs     = require('fs');
const path   = require('path');
const tls    = require('tls');
const net    = require('net');
const crypto = require('crypto');

// ─── Constants ───────────────────────────────────────────────────────────────

const MAX_FILE_SIZE    = 512 * 1024;  // skip files > 512 KB
const MAX_FILES        = 5000;        // safety cap on total files walked
const SCAN_EXTENSIONS  = new Set([
  '.js', '.ts', '.mjs', '.cjs',       // JavaScript / TypeScript
  '.go',                               // Go
  '.py',                               // Python
  '.java', '.kt', '.scala',           // JVM
  '.rb',                               // Ruby
  '.php',                              // PHP
  '.cs', '.vb',                        // .NET
  '.c', '.cpp', '.h', '.hpp',         // C/C++
  '.rs',                               // Rust
  '.swift',                            // Swift
  '.yaml', '.yml', '.json', '.toml',  // Config / manifests
  '.env', '.conf', '.cfg', '.ini',    // Config files
  '.sh', '.bash', '.zsh',             // Shell
  '.tf', '.hcl',                      // Terraform
  '.dockerfile', '',                   // Dockerfile (no extension)
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', 'vendor', '__pycache__',
  'dist', 'build', 'out', 'target', '.cache', '.next',
  'coverage', '.nyc_output', 'tmp', 'temp',
]);

// ─── Code scan patterns ───────────────────────────────────────────────────────
// Each rule: { id, severity, area, title, detail, recommendation, nistRef, pattern }
// pattern is a RegExp tested against each matching line of source code.

const CODE_RULES = [
  // Vulnerable OpenSSL / Go / BoringSSL version pinning
  {
    id: 'SCA-OPENSSL-OLD', severity: 'critical', area: 'sca-deps',
    title: 'Pinned OpenSSL version < 3.5 (cannot support hybrid PQ KEX)',
    detail: 'OpenSSL versions below 3.5 do not support X25519MLKEM768 hybrid key exchange. Servers built against these versions cannot negotiate post-quantum TLS.',
    recommendation: 'Upgrade to OpenSSL 3.5+ to enable ML-KEM hybrid KEX (FIPS 203). Update Dockerfiles, build scripts, and base images.',
    nistRef: 'SC-8 · SC-12 | NIST FIPS 203 | draft-ietf-tls-ecdhe-mlkem-05',
    pattern: /openssl[:\s\/\-_]+(0\.|1\.|2\.|3\.[0-4])/i,
  },
  {
    id: 'SCA-GO-OLD', severity: 'high', area: 'sca-deps',
    title: 'Go version < 1.24 pinned (no ML-KEM hybrid KEX support)',
    detail: 'Go 1.24+ is required for the built-in X25519MLKEM768 TLS 1.3 key share (crypto/tls). Earlier versions only support classical ECDHE.',
    recommendation: 'Update go.mod go directive and all Dockerfiles to Go 1.24 or later.',
    nistRef: 'SC-8 · SC-12 | NIST FIPS 203',
    pattern: /\bgo\s+1\.(1[0-9]|2[0-3])\b/i,
  },
  // Hardcoded private keys / secrets
  {
    id: 'SCA-HARDCODED-PRIVATE-KEY', severity: 'critical', area: 'sca-secrets',
    title: 'Potential hardcoded RSA/EC private key in source code',
    detail: 'A PEM private key header was found in source code. Committing private keys to version control exposes them to anyone with repository access and to git history permanently.',
    recommendation: 'Remove the key immediately. Rotate it. Store secrets in a secrets manager (Vault, AWS Secrets Manager, Render env vars). Audit git history with gitleaks/truffleHog.',
    nistRef: 'SC-12 · SC-17 | NIST SP 800-57',
    pattern: /-----BEGIN (RSA|EC|PRIVATE|OPENSSH|DSA) PRIVATE KEY-----/,
  },
  {
    id: 'SCA-HARDCODED-CERT', severity: 'medium', area: 'sca-secrets',
    title: 'Hardcoded PEM certificate found in source code',
    detail: 'A PEM certificate was found inline in source. While less severe than a private key, hardcoded certs cannot be rotated without a code change and create certificate pinning risk.',
    recommendation: 'Move certificates to environment variables or a mounted secret. Avoid pinning leaf certificates.',
    nistRef: 'SC-12 · SC-17',
    pattern: /-----BEGIN CERTIFICATE-----/,
  },
  // Weak/legacy crypto API calls
  {
    id: 'SCA-MD5-USAGE', severity: 'high', area: 'sca-crypto',
    title: 'MD5 hash function in use',
    detail: 'MD5 is cryptographically broken and must not be used for security purposes. It is trivially collision-attacked (Flame malware). Even under quantum threat, MD5 was already broken classically.',
    recommendation: 'Replace with SHA-256 or SHA-3. For password hashing use Argon2id.',
    nistRef: 'SC-13 | NIST SP 800-131A Rev 2',
    pattern: /\b(md5|MD5)\s*[\(:\[]/,
  },
  {
    id: 'SCA-SHA1-SECURITY', severity: 'medium', area: 'sca-crypto',
    title: 'SHA-1 in use for a security-sensitive operation',
    detail: 'SHA-1 was deprecated by NIST in 2011 and is formally disallowed by NIST SP 800-131A Rev 2 for digital signatures. While collision-attacked, it is not yet broken for HMAC.',
    recommendation: 'Migrate to SHA-256 or SHA-3. Especially critical for certificate signatures and key derivation.',
    nistRef: 'SC-13 | NIST SP 800-131A Rev 2',
    pattern: /\b(sha1|SHA1|sha-1|SHA-1)\s*[\(:\[]/,
  },
  {
    id: 'SCA-DES-3DES', severity: 'critical', area: 'sca-crypto',
    title: 'DES or 3DES cipher in use',
    detail: 'DES (56-bit) is trivially broken. 3DES (TDEA) has a 64-bit block size making it vulnerable to SWEET32 birthday attacks and was deprecated by NIST in 2023.',
    recommendation: 'Replace with AES-256-GCM or ChaCha20-Poly1305.',
    nistRef: 'SC-13 | NIST SP 800-67 Rev 2 | NIST SP 800-131A Rev 2',
    pattern: /\b(DES|3DES|TDEA|des3|triple.?des|createCipheriv\s*\(\s*['"]des)/i,
  },
  {
    id: 'SCA-RC4', severity: 'critical', area: 'sca-crypto',
    title: 'RC4 stream cipher in use',
    detail: 'RC4 is broken. Its key scheduling produces biased outputs exploitable in real-world TLS attacks (BEAST, RC4 Bar-Mitzvah). Prohibited by RFC 7465.',
    recommendation: 'Remove all RC4 usage. Use AES-256-GCM or ChaCha20-Poly1305.',
    nistRef: 'SC-13 | RFC 7465',
    pattern: /\b(RC4|rc4|ARCFOUR|arcfour)\b/,
  },
  {
    id: 'SCA-RSA-SMALL-KEY', severity: 'high', area: 'sca-crypto',
    title: 'RSA key size below 2048 bits specified in code',
    detail: 'RSA keys smaller than 2048 bits are deprecated by NIST SP 800-131A. 1024-bit RSA is factorable with current hardware. Under Shor\'s algorithm any RSA key is vulnerable to a CRQC.',
    recommendation: 'Use RSA-3072 or RSA-4096 as a minimum transitional measure. Prefer ECDSA P-384 or plan for ML-DSA (FIPS 204).',
    nistRef: 'SC-12 · SC-17 | NIST SP 800-131A Rev 2',
    pattern: /\brsa\b.{0,40}(512|768|1024)\b|\bgenerateKeyPair\s*\(\s*['"]rsa['"],\s*\{\s*modulusLength:\s*(512|768|1024)/i,
  },
  {
    id: 'SCA-TLS-MIN-VERSION', severity: 'medium', area: 'sca-tls',
    title: 'TLS minimum version set below TLS 1.2',
    detail: 'Code explicitly sets a TLS minimum version below TLS 1.2. TLS 1.0 and 1.1 are deprecated under RFC 8996 and subject to known attacks.',
    recommendation: 'Set minVersion: "TLSv1.2" as an absolute minimum; prefer "TLSv1.3".',
    nistRef: 'SC-8 | RFC 8996',
    pattern: /min[Vv]ersion\s*[:=]\s*['"]TLSv1(\.[01])?['"]/,
  },
  {
    id: 'SCA-REJECT-UNAUTHORIZED-FALSE', severity: 'high', area: 'sca-tls',
    title: 'TLS certificate verification disabled (rejectUnauthorized: false)',
    detail: 'Disabling TLS certificate verification allows man-in-the-middle attacks. Any certificate, including self-signed or attacker-controlled ones, will be accepted.',
    recommendation: 'Remove rejectUnauthorized: false in production. Use proper CA bundles or NODE_EXTRA_CA_CERTS for custom CAs.',
    nistRef: 'SC-8 · SC-17 | NIST SP 800-52 Rev 2',
    pattern: /rejectUnauthorized\s*[:=]\s*false/,
  },
  {
    id: 'SCA-NODE-TLS-REJECT-ENV', severity: 'high', area: 'sca-tls',
    title: 'NODE_TLS_REJECT_UNAUTHORIZED=0 set in code or config',
    detail: 'Setting NODE_TLS_REJECT_UNAUTHORIZED to 0 disables TLS certificate verification for the entire Node.js process. This is extremely dangerous in production.',
    recommendation: 'Remove this setting. Never use NODE_TLS_REJECT_UNAUTHORIZED=0 in production.',
    nistRef: 'SC-8 · SC-17',
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?/,
  },
  {
    id: 'SCA-CLASSIC-RANDOM', severity: 'medium', area: 'sca-crypto',
    title: 'Math.random() used where cryptographic randomness is required',
    detail: 'Math.random() is not cryptographically secure and is predictable. Using it for token generation, nonces, or key material is a serious vulnerability.',
    recommendation: 'Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for all security-sensitive random values.',
    nistRef: 'SC-13 | NIST SP 800-90A',
    pattern: /Math\.random\(\)\s*[*+\-]\s*\d+.*?(token|secret|key|nonce|salt|id|session)/i,
  },
];

// ─── Certificate file extensions ──────────────────────────────────────────────
const CERT_EXTENSIONS = new Set(['.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.p7b', '.jks']);

// Rule areas whose matched line is potentially live secret material (private
// keys, embedded certs). These findings must NEVER return the raw matched
// text over the API — the endpoint that serves this JSON is reachable
// without authentication in the current deployment, and the CODE_RULES
// below are specifically designed to match -----BEGIN ... PRIVATE KEY-----
// blocks. Returning a 200-character snippet of a match was, in effect, a
// secret-disclosure oracle. We keep the file path and line number (the
// operator has their own filesystem access to go look) and replace the
// snippet with a hash so duplicate/changed-secret detection still works
// without ever putting the secret itself on the wire.
const REDACT_SNIPPET_AREAS = new Set(['sca-secrets']);

function redactedSnippet(line) {
  const hash = crypto.createHash('sha256').update(line).digest('hex').slice(0, 16);
  return `[redacted — matched line hash ${hash}, ${line.length} chars]`;
}

// ─── File walker ──────────────────────────────────────────────────────────────

function walkDir(rootPath, extensions, maxFiles) {
  const files = [];
  const stack = [rootPath];

  while (stack.length > 0 && files.length < maxFiles) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }

    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      if (entry.name.startsWith('.') && entry.name !== '.env') continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.has(ext) || (extensions.has('') && entry.name === 'Dockerfile')) {
          files.push(fullPath);
        }
      }
    }
  }

  return files;
}

// ─── Code / SCA scan ─────────────────────────────────────────────────────────

async function runCodeScan(rootPath, domain) {
  // Validate path exists and is a directory
  let stat;
  try { stat = fs.statSync(rootPath); } catch {
    throw new Error(`Path does not exist: ${rootPath}`);
  }
  if (!stat.isDirectory()) throw new Error(`Path is not a directory: ${rootPath}`);

  const files    = walkDir(rootPath, SCAN_EXTENSIONS, MAX_FILES);
  const findings = [];
  let scanned    = 0;

  for (const filePath of files) {
    let content;
    try {
      const s = fs.statSync(filePath);
      if (s.size > MAX_FILE_SIZE) continue;
      content = fs.readFileSync(filePath, 'utf8');
    } catch { continue; }

    scanned++;
    const relPath = path.relative(rootPath, filePath);
    const lines   = content.split('\n');

    for (const rule of CODE_RULES) {
      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          // Skip commented lines for most rules
          const trimmed = lines[i].trim();
          if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
            continue;
          }
          const rawLine = lines[i].trim();
          findings.push({
            id:             rule.id,
            severity:       rule.severity,
            area:           rule.area,
            name:           rule.title,
            file:           relPath,
            line:           i + 1,
            snippet:        REDACT_SNIPPET_AREAS.has(rule.area) ? redactedSnippet(rawLine) : rawLine.slice(0, 200),
            detail:         rule.detail,
            recommendation: rule.recommendation,
            nistRef:        rule.nistRef,
          });
          break; // one match per file per rule is sufficient
        }
      }
    }
  }

  // De-duplicate (same rule in same file)
  const seen = new Set();
  const deduped = findings.filter(f => {
    const key = `${f.id}::${f.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    rootPath,
    domain,
    filesScanned:     scanned,
    filesTotal:       files.length,
    findings:         deduped,
    findingsBySeverity: {
      critical: deduped.filter(f => f.severity === 'critical').length,
      high:     deduped.filter(f => f.severity === 'high').length,
      medium:   deduped.filter(f => f.severity === 'medium').length,
      low:      deduped.filter(f => f.severity === 'low').length,
      info:     deduped.filter(f => f.severity === 'info').length,
    },
    scannedAt: new Date().toISOString(),
  };
}

// ─── PKI / certificate scan ───────────────────────────────────────────────────

function parsePEMCert(pemContent, filePath) {
  // Extract each certificate block
  const certs = [];
  const pemRegex = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let match;

  while ((match = pemRegex.exec(pemContent)) !== null) {
    try {
      // Use TLS SecureContext to validate the cert and extract metadata
      const ctx = tls.createSecureContext({ ca: match[0] });
      // We can't easily extract parsed fields from SecureContext
      // So we use the built-in crypto module instead
      const crypto = require('crypto');
      const der    = Buffer.from(match[1].replace(/\s+/g, ''), 'base64');

      // Create an X509Certificate (Node 15.6+)
      if (crypto.X509Certificate) {
        const cert = new crypto.X509Certificate(der);
        certs.push({
          file:       filePath,
          subject:    cert.subject,
          issuer:     cert.issuer,
          validFrom:  cert.validFrom,
          validTo:    cert.validTo,
          serialNumber: cert.serialNumber,
          fingerprint:  cert.fingerprint256,
          publicKeyType: cert.publicKey?.asymmetricKeyType || 'unknown',
          keySize:    cert.publicKey?.asymmetricKeyDetails?.modulusLength ||
                      cert.publicKey?.asymmetricKeyDetails?.namedCurve || null,
          subjectAltName: cert.subjectAltName || null,
        });
      }
    } catch {}
  }

  return certs;
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const exp = new Date(dateStr);
  return Math.round((exp - Date.now()) / (1000 * 60 * 60 * 24));
}

async function runPKIScan(rootPath, domain) {
  let stat;
  try { stat = fs.statSync(rootPath); } catch {
    throw new Error(`Path does not exist: ${rootPath}`);
  }
  if (!stat.isDirectory()) throw new Error(`Path is not a directory: ${rootPath}`);

  const certFiles = walkDir(rootPath, CERT_EXTENSIONS, MAX_FILES);
  const parsedCerts = [];

  for (const filePath of certFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const relPath = path.relative(rootPath, filePath);
      const certs   = parsePEMCert(content, relPath);
      parsedCerts.push(...certs);
    } catch {}
  }

  const findings = [];

  for (const cert of parsedCerts) {
    const days = daysUntil(cert.validTo);

    // Expired
    if (days !== null && days < 0) {
      findings.push({
        id:             'PKI-CERT-EXPIRED',
        severity:       'critical',
        area:           'pki',
        title:          `Expired certificate found`,
        file:           cert.file,
        detail:         `Certificate for ${cert.subject?.split('\n')[0]} expired ${Math.abs(days)} day(s) ago (${cert.validTo}).`,
        recommendation: 'Remove or replace immediately. Verify this is not in production use.',
        nistRef:        'SC-17 · IA-5',
      });
    } else if (days !== null && days < 14) {
      findings.push({
        id:             'PKI-CERT-EXPIRY-CRITICAL',
        severity:       'high',
        area:           'pki',
        title:          `Certificate expires in ${days} days`,
        file:           cert.file,
        detail:         `Certificate expires: ${cert.validTo}. Critical renewal window.`,
        recommendation: 'Renew immediately.',
        nistRef:        'SC-17',
      });
    } else if (days !== null && days < 30) {
      findings.push({
        id:             'PKI-CERT-EXPIRY-WARN',
        severity:       'medium',
        area:           'pki',
        title:          `Certificate expires in ${days} days`,
        file:           cert.file,
        detail:         `Certificate expires: ${cert.validTo}.`,
        recommendation: 'Initiate renewal within the next two weeks.',
        nistRef:        'SC-17',
      });
    }

    // Classical key type — RSA or ECDSA (quantum-vulnerable)
    const keyType = (cert.publicKeyType || '').toLowerCase();
    if (keyType === 'rsa') {
      const bits = cert.keySize;
      if (bits && bits < 2048) {
        findings.push({
          id:             'PKI-RSA-WEAK',
          severity:       'critical',
          area:           'pki',
          title:          `Weak RSA key: ${bits} bits`,
          file:           cert.file,
          detail:         `RSA-${bits} is below NIST SP 800-131A's 2048-bit minimum. Factorable with current hardware.`,
          recommendation: 'Replace with RSA-3072+ or ECDSA P-384. Plan migration to ML-DSA (FIPS 204) by 2027.',
          nistRef:        'SC-12 · SC-17 | NIST SP 800-131A Rev 2',
        });
      } else {
        findings.push({
          id:             'PKI-RSA-CLASSICAL',
          severity:       'medium',
          area:           'pki',
          title:          `RSA-${bits || '?'} certificate (quantum-vulnerable — TNFL risk)`,
          file:           cert.file,
          detail:         `RSA signatures are vulnerable to Shor's algorithm on a CRQC. Trust-Now-Forge-Later: a future CRQC could forge certificates for this key.`,
          recommendation: 'Track CA/Browser Forum timeline for ML-DSA certificates (expected 2027+). Plan certificate migration.',
          nistRef:        'SC-12 · SC-17 | NIST FIPS 204 | NIST IR 8547',
        });
      }
    } else if (keyType === 'ec') {
      findings.push({
        id:             'PKI-ECDSA-CLASSICAL',
        severity:       'medium',
        area:           'pki',
        title:          `ECDSA certificate (quantum-vulnerable — TNFL risk)`,
        file:           cert.file,
        detail:         `ECDSA (${cert.keySize || 'unknown curve'}) is vulnerable to Shor's algorithm. Quantum-safe alternative: ML-DSA (FIPS 204).`,
        recommendation: 'Plan migration to ML-DSA certificates when CAs offer them (expected 2027+).',
        nistRef:        'SC-12 · SC-17 | NIST FIPS 204 | NIST IR 8547',
      });
    }
  }

  // De-duplicate at file+id level
  const seen = new Set();
  const deduped = findings.filter(f => {
    const key = `${f.id}::${f.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    rootPath,
    domain,
    certificatesParsed: parsedCerts.length,
    filesScanned:       certFiles.length,
    certificates:       parsedCerts,
    findings:           deduped,
    findingsBySeverity: {
      critical: deduped.filter(f => f.severity === 'critical').length,
      high:     deduped.filter(f => f.severity === 'high').length,
      medium:   deduped.filter(f => f.severity === 'medium').length,
      low:      deduped.filter(f => f.severity === 'low').length,
      info:     deduped.filter(f => f.severity === 'info').length,
    },
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { runCodeScan, runPKIScan };
