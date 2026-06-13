'use strict';

/**
 * CipherQ — Network & Protocol Security Scanner
 * Checks: Port scanning, SSH PQC readiness, SMTP STARTTLS,
 *         FTP security, banner grabbing, IPv6 surface
 */

const net  = require('net');
const tls  = require('tls');
const dns  = require('dns').promises;

// ─── Interesting ports to probe ───────────────────────────────────────────────
const PORT_DEFINITIONS = [
  { port: 21,    proto: 'FTP',           severity: 'high',   note: 'Plaintext file transfer — credentials sent unencrypted' },
  { port: 22,    proto: 'SSH',           severity: 'info',   note: 'Secure Shell — probe for weak key exchange algorithms' },
  { port: 23,    proto: 'Telnet',        severity: 'critical', note: 'Cleartext remote access protocol — no encryption whatsoever' },
  { port: 25,    proto: 'SMTP',          severity: 'info',   note: 'Mail transfer — probe for STARTTLS and TLS quality' },
  { port: 53,    proto: 'DNS',           severity: 'info',   note: 'DNS service — covered by DNS security module' },
  { port: 80,    proto: 'HTTP',          severity: 'info',   note: 'Plaintext HTTP — check redirect to HTTPS' },
  { port: 110,   proto: 'POP3',          severity: 'medium', note: 'Legacy mail retrieval — use IMAPS/POP3S instead' },
  { port: 143,   proto: 'IMAP',          severity: 'medium', note: 'Mail access — check STARTTLS enforcement' },
  { port: 389,   proto: 'LDAP',          severity: 'high',   note: 'Plaintext LDAP — directory data exposed without encryption' },
  { port: 443,   proto: 'HTTPS',         severity: 'info',   note: 'TLS — covered by TLS scanner module' },
  { port: 445,   proto: 'SMB',           severity: 'critical', note: 'Windows file sharing — should never be internet-facing' },
  { port: 587,   proto: 'SMTP Submission', severity: 'info', note: 'Mail submission — probe STARTTLS' },
  { port: 636,   proto: 'LDAPS',         severity: 'info',   note: 'LDAP over TLS — probe certificate and cipher' },
  { port: 993,   proto: 'IMAPS',         severity: 'info',   note: 'IMAP over TLS' },
  { port: 995,   proto: 'POP3S',         severity: 'info',   note: 'POP3 over TLS' },
  { port: 1433,  proto: 'MSSQL',         severity: 'critical', note: 'Microsoft SQL Server — should never be internet-facing' },
  { port: 3306,  proto: 'MySQL',         severity: 'critical', note: 'MySQL — should never be internet-facing' },
  { port: 3389,  proto: 'RDP',           severity: 'critical', note: 'Remote Desktop — high-value ransomware target' },
  { port: 5432,  proto: 'PostgreSQL',    severity: 'critical', note: 'PostgreSQL — should never be internet-facing' },
  { port: 5900,  proto: 'VNC',           severity: 'critical', note: 'VNC remote desktop — often unencrypted' },
  { port: 6379,  proto: 'Redis',         severity: 'critical', note: 'Redis — commonly unauthenticated, should never be internet-facing' },
  { port: 8080,  proto: 'HTTP-Alt',      severity: 'medium', note: 'Alternative HTTP — often dev/admin interfaces' },
  { port: 8443,  proto: 'HTTPS-Alt',     severity: 'medium', note: 'Alternative HTTPS — often admin panels' },
  { port: 8888,  proto: 'HTTP-Dev',      severity: 'medium', note: 'Development server port' },
  { port: 9200,  proto: 'Elasticsearch', severity: 'critical', note: 'Elasticsearch — commonly unauthenticated, massive data exposure risk' },
  { port: 9300,  proto: 'Elasticsearch-Cluster', severity: 'critical', note: 'Elasticsearch cluster port — should never be internet-facing' },
  { port: 27017, proto: 'MongoDB',       severity: 'critical', note: 'MongoDB — commonly unauthenticated, should never be internet-facing' },
  { port: 5601,  proto: 'Kibana',        severity: 'high',   note: 'Kibana dashboard — often exposes sensitive log data' },
  { port: 4444,  proto: 'Metasploit',    severity: 'critical', note: 'Common Metasploit/backdoor port' },
  { port: 6666,  proto: 'Backdoor',      severity: 'critical', note: 'Common backdoor/IRC port' },
  { port: 9000,  proto: 'Dev-Alt',       severity: 'medium', note: 'Alternative development port (PHP-FPM, SonarQube)' },
  { port: 2375,  proto: 'Docker',        severity: 'critical', note: 'Docker API (unencrypted) — full container management access if exposed' },
  { port: 2376,  proto: 'Docker-TLS',    severity: 'high',   note: 'Docker API (TLS) — should be firewall-restricted' },
  { port: 6443,  proto: 'Kubernetes-API', severity: 'critical', note: 'Kubernetes API server — should never be publicly accessible' },
  { port: 10250, proto: 'Kubelet',       severity: 'critical', note: 'Kubernetes Kubelet API — code execution if exposed' },
];

// ─── SSH algorithm classification ─────────────────────────────────────────────
// Algorithms considered quantum-safe or hybrid-PQ for key exchange
const SSH_PQ_KEX = [
  'mlkem768x25519-sha256',       // OpenSSH 9.0+ hybrid PQ KEX (IETF draft)
  'sntrup761x25519-sha512@openssh.com', // NTRU Prime hybrid (OpenSSH 8.5–8.9)
  'mlkem1024x25519-sha256',
];

// Classical SSH KEX algorithms (quantum-vulnerable)
const SSH_CLASSICAL_KEX = [
  'curve25519-sha256', 'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
  'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1',
  'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
];

// Deprecated / broken SSH algorithms
const SSH_DEPRECATED_KEX = [
  'diffie-hellman-group1-sha1',  // Logjam-vulnerable
  'diffie-hellman-group-exchange-sha1',
  'gss-gex-sha1-', 'gss-group1-sha1-',
];

const SSH_DEPRECATED_HOSTKEY = ['ssh-dss', 'ssh-rsa'];  // RSA < 2048 / DSA
const SSH_DEPRECATED_CIPHER  = ['3des-cbc', 'aes128-cbc', 'aes256-cbc', 'arcfour', 'blowfish-cbc'];
const SSH_DEPRECATED_MAC     = ['hmac-md5', 'hmac-sha1', 'hmac-md5-96', 'hmac-sha1-96'];

// ─── Utility: TCP port probe ──────────────────────────────────────────────────
function probePort(ip, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let banner = '';
    let resolved = false;

    const done = (open, b) => {
      if (!resolved) { resolved = true; sock.destroy(); resolve({ open, banner: b || null }); }
    };

    sock.setTimeout(timeoutMs);
    sock.connect(port, ip, () => { /* connected */ });

    sock.on('connect', () => {
      // Give the server a moment to send a banner
      setTimeout(() => done(true, banner), 800);
    });

    sock.on('data', (d) => {
      banner += d.toString('utf8', 0, 256);
    });

    sock.on('timeout', () => done(false, null));
    sock.on('error',   () => done(false, null));
  });
}

// ─── 1. Port scan ─────────────────────────────────────────────────────────────
async function portScan(ip, hostname) {
  const result = { ip, hostname, openPorts: [], findings: [] };

  // Probe all ports with concurrency
  const concurrency = 20;
  for (let i = 0; i < PORT_DEFINITIONS.length; i += concurrency) {
    const batch = PORT_DEFINITIONS.slice(i, i + concurrency);
    const probes = await Promise.all(
      batch.map(async (def) => {
        const { open, banner } = await probePort(ip, def.port);
        return { ...def, open, banner };
      })
    );

    for (const p of probes) {
      if (p.open) {
        result.openPorts.push({ port: p.port, proto: p.proto, banner: p.banner });

        // Critical exposed services
        if (['critical','high'].includes(p.severity) && ![22, 25, 80, 443, 587, 636, 993, 995].includes(p.port)) {
          result.findings.push({
            id:     `PORT-${p.port}-EXPOSED`,
            severity: p.severity,
            area:   'port-exposure',
            title:  `${p.proto} (port ${p.port}) exposed to internet`,
            detail: `Port ${p.port} (${p.proto}) is open and accessible from the internet. ${p.note}.${p.banner ? ` Banner: "${p.banner.trim().slice(0, 100)}"` : ''}`,
            recommendation: `Restrict access to port ${p.port} via firewall rules. Only allow from authorised management IP ranges.`,
            nistRef: 'CM-7 · AC-3 · SC-7',
            priority: p.severity === 'critical' ? 'P1' : 'P2',
          });
        }

        // FTP specifically
        if (p.port === 21) {
          result.findings.push({
            id: 'PORT-FTP-PLAINTEXT',
            severity: 'high',
            area: 'port-exposure',
            title: 'FTP (plaintext) exposed',
            detail: `FTP transmits credentials and data in cleartext. ${p.banner ? `Server banner: "${p.banner.trim()}"` : ''}. Active on port 21.`,
            recommendation: 'Replace with SFTP (SSH file transfer) or FTPS (FTP over TLS). Disable cleartext FTP entirely.',
            nistRef: 'SC-8 · IA-5 | RFC 4251',
            priority: 'P1',
          });
        }

        // Telnet
        if (p.port === 23) {
          result.findings.push({
            id: 'PORT-TELNET-EXPOSED',
            severity: 'critical',
            area: 'port-exposure',
            title: 'Telnet exposed — cleartext remote access',
            detail: `Telnet provides no encryption. All keystrokes including passwords are transmitted in cleartext and trivially captured by a network observer.`,
            recommendation: 'Disable Telnet immediately. Replace with SSH.',
            nistRef: 'SC-8 · IA-5',
            priority: 'P1',
          });
        }
      }
    }
  }

  if (result.openPorts.length === 0) {
    result.findings.push({
      id: 'PORT-SCAN-COMPLETE',
      severity: 'info',
      area: 'port-exposure',
      title: `Port scan complete — only expected ports open`,
      detail: `Scanned ${PORT_DEFINITIONS.length} ports on ${ip}. No unexpected services detected.`,
    });
  }

  return result;
}

// ─── 2. SSH security probe ────────────────────────────────────────────────────
// Parses the SSH handshake to extract algorithm lists from the KEXINIT packet

function parseSSHKEXINIT(buf) {
  // SSH packet: 4-byte length, 1-byte padding length, 1-byte message type, payload
  // After length+padding bytes, offset 6 = message code (20 = KEXINIT)
  // Then 16 bytes cookie, then name-list fields
  if (buf.length < 22) return null;
  const msgCode = buf[5];
  if (msgCode !== 20) return null; // Not KEXINIT

  let offset = 22; // Skip length(4) + padding_len(1) + msg_code(1) + cookie(16)

  function readNameList() {
    if (offset + 4 > buf.length) return [];
    const len = buf.readUInt32BE(offset);
    offset += 4;
    if (offset + len > buf.length) return [];
    const str = buf.slice(offset, offset + len).toString('utf8');
    offset += len;
    return str.split(',').map(s => s.trim()).filter(Boolean);
  }

  return {
    kex_algorithms:               readNameList(),
    server_host_key_algorithms:   readNameList(),
    encryption_client_to_server:  readNameList(),
    encryption_server_to_client:  readNameList(),
    mac_client_to_server:         readNameList(),
    mac_server_to_client:         readNameList(),
    compression_client_to_server: readNameList(),
    compression_server_to_client: readNameList(),
  };
}

async function probeSSH(ip, hostname) {
  return new Promise((resolve) => {
    const result = {
      ip, hostname,
      available: false,
      banner: null,
      algorithms: null,
      findings: [],
    };

    const sock = new net.Socket();
    let data = Buffer.alloc(0);
    let bannerReceived = false;
    let resolved = false;

    const done = () => { if (!resolved) { resolved = true; sock.destroy(); resolve(result); } };

    sock.setTimeout(8000);
    sock.connect(22, ip, () => {
      // Send our own client banner to trigger server KEXINIT
      sock.write('SSH-2.0-CipherQ_Scanner_1.0\r\n');
    });

    sock.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);

      // Extract banner (first line)
      if (!bannerReceived && data.includes(0x0A)) {
        const banner = data.slice(0, data.indexOf(0x0A)).toString('utf8').trim();
        if (banner.startsWith('SSH-')) {
          result.banner = banner;
          result.available = true;
          bannerReceived = true;
        }
      }

      // Try to parse KEXINIT (arrives after banner)
      if (bannerReceived && data.length > 35) {
        // Find the start of the binary packet (after our banner exchange)
        // The KEXINIT packet starts after SSH banner lines
        const bannerEnd = data.indexOf('\n') + 1;
        if (bannerEnd > 0 && data.length > bannerEnd + 20) {
          const kexBuf = data.slice(bannerEnd);
          const algorithms = parseSSHKEXINIT(kexBuf);
          if (algorithms) {
            result.algorithms = algorithms;
            analyseSSHAlgorithms(result);
            done();
          }
        }
      }
    });

    sock.on('timeout', () => { analyseSSHAlgorithms(result); done(); });
    sock.on('error',   done);
    sock.on('end',     () => { analyseSSHAlgorithms(result); done(); });

    // Force resolution after 6s even without KEXINIT parse
    setTimeout(() => done(), 6000);
  });
}

function analyseSSHAlgorithms(result) {
  if (!result.available) return;
  if (!result.algorithms) return;

  const algs = result.algorithms;
  const kex  = algs.kex_algorithms || [];
  const hk   = algs.server_host_key_algorithms || [];
  const enc  = algs.encryption_client_to_server || [];
  const mac  = algs.mac_client_to_server || [];

  // PQ KEX check
  const hasPQKex   = kex.some(k => SSH_PQ_KEX.some(p => k.includes(p)));
  const hasDepKex  = kex.filter(k => SSH_DEPRECATED_KEX.some(d => k.includes(d)));
  const hasDepHK   = hk.filter(k => SSH_DEPRECATED_HOSTKEY.includes(k));
  const hasDepEnc  = enc.filter(k => SSH_DEPRECATED_CIPHER.includes(k));
  const hasDepMAC  = mac.filter(k => SSH_DEPRECATED_MAC.includes(k));

  // SSH version from banner
  if (result.banner) {
    const versionMatch = result.banner.match(/SSH-2\.0-OpenSSH[_-](\d+\.\d+)/i);
    if (versionMatch) {
      const ver = parseFloat(versionMatch[1]);
      result.sshVersion = `OpenSSH ${versionMatch[1]}`;
      if (ver < 8.0) {
        result.findings.push({
          id: 'SSH-OUTDATED-VERSION',
          severity: 'high',
          area: 'ssh-security',
          title: `Outdated OpenSSH version: ${versionMatch[1]}`,
          detail: `OpenSSH ${versionMatch[1]} is outdated. Versions before 8.0 lack hybrid post-quantum key exchange support (added in 8.5 as sntrup761x25519, enhanced in 9.0 with mlkem768x25519). Multiple CVEs may apply depending on exact version.`,
          recommendation: 'Upgrade to OpenSSH 9.0+ to gain access to hybrid PQ KEX (mlkem768x25519-sha256).',
          nistRef: 'SI-2 · SC-8 | NIST IR 8547',
          priority: 'P2',
        });
      }
    }
  }

  // PQ KEX readiness
  if (!hasPQKex) {
    result.findings.push({
      id: 'SSH-NO-PQ-KEX',
      severity: 'medium',
      area: 'ssh-security',
      title: 'SSH has no post-quantum key exchange algorithm',
      detail: `SSH server does not advertise any hybrid post-quantum KEX algorithm. Advertised KEX algorithms: ${kex.slice(0,5).join(', ')}. SSH sessions are subject to the same Harvest-Now-Decrypt-Later threat as TLS — an adversary recording traffic today can decrypt it with a CRQC. OpenSSH 9.0+ supports mlkem768x25519-sha256 by default.`,
      recommendation: 'Upgrade to OpenSSH 9.0+ and verify mlkem768x25519-sha256 appears first in the KEX negotiation. Confirm with: ssh -vvv host 2>&1 | grep kex.',
      nistRef: 'SC-8 · SC-12 | NIST IR 8547 | draft-ietf-sshm-hybrid-kex',
      priority: 'P1',
    });
  } else {
    result.findings.push({
      id: 'SSH-PQ-KEX-PRESENT',
      severity: 'info',
      area: 'ssh-security',
      title: `SSH hybrid post-quantum KEX detected: ${kex.filter(k => SSH_PQ_KEX.some(p => k.includes(p))).join(', ')}`,
      detail: `SSH server advertises at least one hybrid PQ key exchange algorithm. HNDL risk on SSH sessions is mitigated.`,
    });
  }

  // Deprecated KEX
  if (hasDepKex.length > 0) {
    result.findings.push({
      id: 'SSH-DEPRECATED-KEX',
      severity: hasDepKex.includes('diffie-hellman-group1-sha1') ? 'critical' : 'high',
      area: 'ssh-security',
      title: `Deprecated SSH key exchange algorithms: ${hasDepKex.join(', ')}`,
      detail: `Server advertises deprecated KEX algorithms including ${hasDepKex.join(', ')}. ${hasDepKex.includes('diffie-hellman-group1-sha1') ? 'diffie-hellman-group1-sha1 uses a 768-bit or 1024-bit DH group vulnerable to the Logjam attack.' : 'These algorithms are deprecated in RFC 8732.'}`,
      recommendation: 'Remove deprecated KEX algorithms from sshd_config: KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,ecdh-sha2-nistp256',
      nistRef: 'SC-8 | RFC 8732',
      priority: hasDepKex.includes('diffie-hellman-group1-sha1') ? 'P1' : 'P2',
    });
  }

  // Deprecated host key algorithms
  if (hasDepHK.length > 0) {
    result.findings.push({
      id: 'SSH-DEPRECATED-HOST-KEY',
      severity: 'medium',
      area: 'ssh-security',
      title: `Deprecated SSH host key algorithms: ${hasDepHK.join(', ')}`,
      detail: `Server advertises deprecated host key algorithms: ${hasDepHK.join(', ')}. ssh-rsa uses SHA-1 signature by default (deprecated in RFC 8332). ssh-dss (DSA) is limited to 1024-bit keys. These are vulnerable to quantum attack via Shor's algorithm.`,
      recommendation: 'Remove ssh-rsa and ssh-dss from HostKeyAlgorithms. Use ecdsa-sha2-nistp256 or ssh-ed25519 today; adopt ML-DSA when available.',
      nistRef: 'SC-8 · SC-12 | RFC 8332 | NIST IR 8547',
    });
  }

  // Deprecated ciphers
  if (hasDepEnc.length > 0) {
    result.findings.push({
      id: 'SSH-DEPRECATED-CIPHERS',
      severity: 'medium',
      area: 'ssh-security',
      title: `Deprecated SSH ciphers: ${hasDepEnc.join(', ')}`,
      detail: `Server advertises deprecated or weak cipher suites: ${hasDepEnc.join(', ')}. CBC-mode ciphers are vulnerable to Lucky13 and other padding oracle attacks.`,
      recommendation: 'Restrict to: Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com',
      nistRef: 'SC-8',
    });
  }

  // Deprecated MACs
  if (hasDepMAC.length > 0) {
    result.findings.push({
      id: 'SSH-DEPRECATED-MAC',
      severity: 'medium',
      area: 'ssh-security',
      title: `Deprecated SSH MAC algorithms: ${hasDepMAC.join(', ')}`,
      detail: `Server advertises deprecated MAC algorithms: ${hasDepMAC.join(', ')}. MD5 and SHA-1 based MACs are cryptographically weak.`,
      recommendation: 'Restrict to: MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com',
      nistRef: 'SC-8',
    });
  }
}

// ─── 3. SMTP STARTTLS probe ───────────────────────────────────────────────────
async function probeSMTP(ip, hostname, port = 25) {
  return new Promise((resolve) => {
    const result = { ip, hostname, port, available: false, starttls: false, tls: null, findings: [], banner: null };
    let data = '';
    let stage = 'banner';
    let resolved = false;

    const done = () => { if (!resolved) { resolved = true; sock.destroy(); resolve(result); } };
    const sock = new net.Socket();

    sock.setTimeout(10000);
    sock.connect(port, ip);

    sock.on('connect', () => { result.available = true; });

    sock.on('data', (chunk) => {
      data += chunk.toString();

      if (stage === 'banner' && data.includes('\n')) {
        result.banner = data.split('\n')[0].trim();
        // Send EHLO
        sock.write('EHLO cipherq-scanner.local\r\n');
        stage = 'ehlo';
        data = '';
      } else if (stage === 'ehlo' && data.includes('\n')) {
        result.supportsSTARTTLS = data.toUpperCase().includes('STARTTLS');

        if (result.supportsSTARTTLS) {
          sock.write('STARTTLS\r\n');
          stage = 'starttls';
          data = '';
        } else {
          result.findings.push({
            id: `SMTP-NO-STARTTLS-${port}`,
            severity: port === 25 ? 'medium' : 'high',
            area: 'smtp-security',
            title: `SMTP on port ${port} does not offer STARTTLS`,
            detail: `${hostname}:${port} (${result.banner || 'unknown server'}) does not advertise STARTTLS in its EHLO response. Mail transmitted to/from this server is sent in cleartext, exposing contents and credentials to network interception.`,
            recommendation: 'Enable STARTTLS on the SMTP server. For MTA-to-MTA (port 25), also consider DANE/MTA-STS for authenticated encryption.',
            nistRef: 'SC-8 · SI-8 | RFC 3207',
            priority: 'P1',
          });
          done();
        }
      } else if (stage === 'starttls' && data.includes('220')) {
        // Server said "Go ahead" — upgrade to TLS
        result.starttls = true;
        stage = 'tls';
        data = '';

        const tlsSocket = tls.connect({
          socket: sock,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 5000,
        }, () => {
          const cert   = tlsSocket.getPeerCertificate(true);
          const cipher = tlsSocket.getCipher();
          const proto  = tlsSocket.getProtocol();

          result.tls = { protocol: proto, cipher: cipher?.name, certDaysToExpiry: null };

          // Check TLS version
          if (proto === 'TLSv1' || proto === 'TLSv1.1') {
            result.findings.push({
              id: `SMTP-DEPRECATED-TLS-${port}`,
              severity: 'critical',
              area: 'smtp-security',
              title: `SMTP STARTTLS negotiated deprecated ${proto} on port ${port}`,
              detail: `STARTTLS on ${hostname}:${port} negotiated ${proto} which is deprecated per RFC 8996. Downgrades are trivially forced by a MITM.`,
              recommendation: 'Disable TLS 1.0/1.1 on the SMTP server. Require TLS 1.2 minimum.',
              nistRef: 'SC-8 | RFC 8996',
              priority: 'P1',
            });
          }

          if (cert?.valid_to) {
            const days = Math.round((new Date(cert.valid_to) - new Date()) / 86400000);
            result.tls.certDaysToExpiry = days;
            if (days < 0) {
              result.findings.push({ id: `SMTP-CERT-EXPIRED-${port}`, severity: 'critical', area: 'smtp-security', title: `SMTP TLS certificate EXPIRED on port ${port}`, detail: `Certificate expired ${Math.abs(days)} day(s) ago.`, recommendation: 'Renew immediately.', priority: 'P1' });
            } else if (days < 30) {
              result.findings.push({ id: `SMTP-CERT-EXPIRY-${port}`, severity: 'medium', area: 'smtp-security', title: `SMTP TLS certificate expiring in ${days} days on port ${port}`, detail: `Certificate expires: ${cert.valid_to}.`, recommendation: 'Renew within the next two weeks.' });
            }
          }

          if (!result.findings.some(f => f.area === 'smtp-security' && f.severity !== 'info')) {
            result.findings.push({
              id: `SMTP-STARTTLS-OK-${port}`,
              severity: 'info',
              area: 'smtp-security',
              title: `SMTP STARTTLS working correctly on port ${port}`,
              detail: `${hostname}:${port} — STARTTLS offered, ${proto} negotiated, cipher: ${cipher?.name || 'unknown'}.`,
            });
          }

          tlsSocket.destroy();
          done();
        });

        tlsSocket.on('error', done);
        tlsSocket.setTimeout(5000, done);
      }
    });

    sock.on('timeout', done);
    sock.on('error',   done);

    setTimeout(done, 12000);
  });
}

// ─── 4. IPv6 surface comparison ───────────────────────────────────────────────
async function checkIPv6Surface(hostname) {
  const result = { hostname, findings: [] };

  let aaaaRecords = [];
  try { aaaaRecords = await dns.resolve6(hostname); } catch {}

  if (aaaaRecords.length === 0) {
    result.findings.push({
      id: 'IPV6-NO-AAAA',
      severity: 'info',
      area: 'ipv6',
      title: `No IPv6 (AAAA) records for ${hostname}`,
      detail: 'Host is not reachable over IPv6. If this is intentional, no action required. If IPv6 is expected, configure AAAA records.',
    });
    return result;
  }

  result.ipv6Addresses = aaaaRecords;

  // Check if TLS on IPv6 is also accessible (probe is the same — TLS connect uses DNS)
  result.findings.push({
    id: 'IPV6-SURFACE',
    severity: 'info',
    area: 'ipv6',
    title: `IPv6 surface present: ${aaaaRecords.join(', ')}`,
    detail: `Host is reachable over IPv6. Verify that TLS configuration, security headers, and access controls are identical between IPv4 and IPv6 paths. IPv6 interfaces are commonly forgotten in security hardening.`,
    recommendation: 'Include IPv6 addresses in TLS certificate SANs. Apply identical firewall rules to IPv4 and IPv6. Test with explicit IPv6 connection: curl -6 https://' + hostname,
    nistRef: 'CM-7 · SC-7',
  });

  return result;
}

// ─── Master network scan ──────────────────────────────────────────────────────
async function scanNetworkSecurity(domain, hosts, opts = {}) {
  const { onProgress = null } = opts;
  const allFindings = [];
  const report = { domain, portScans: [], sshScans: [], smtpScans: [], ipv6: [] };

  const step = (msg) => { if (onProgress) onProgress({ phase: 'network-security', message: msg }); };

  // Get unique IPs from reachable hosts
  const ipMap = new Map(); // ip -> hostname
  for (const h of hosts) {
    if (h.dns?.aRecords?.length > 0) {
      ipMap.set(h.dns.aRecords[0], h.hostname);
    }
  }

  const uniqueIPs = [...ipMap.entries()].slice(0, 10); // Cap at 10 IPs

  // Port scans
  step(`Port scanning ${uniqueIPs.length} IPs…`);
  for (const [ip, hostname] of uniqueIPs) {
    const scan = await portScan(ip, hostname);
    report.portScans.push(scan);
    for (const f of scan.findings) allFindings.push({ ...f, hostname });
  }

  // SSH probes (only hosts where port 22 is open)
  const sshHosts = report.portScans.filter(s => s.openPorts.some(p => p.port === 22));
  if (sshHosts.length > 0) {
    step(`Probing SSH algorithms on ${sshHosts.length} hosts…`);
    for (const scan of sshHosts) {
      const ssh = await probeSSH(scan.ip, scan.hostname);
      report.sshScans.push(ssh);
      for (const f of ssh.findings) allFindings.push({ ...f, hostname: ssh.hostname });
    }
  }

  // SMTP probes (only hosts where 25 or 587 are open)
  const smtpHosts = report.portScans.filter(s => s.openPorts.some(p => [25, 587].includes(p.port)));
  if (smtpHosts.length > 0) {
    step(`Probing SMTP STARTTLS on ${smtpHosts.length} hosts…`);
    for (const scan of smtpHosts) {
      const ports = scan.openPorts.filter(p => [25, 587].includes(p.port)).map(p => p.port);
      for (const port of ports) {
        const smtp = await probeSMTP(scan.ip, scan.hostname, port);
        report.smtpScans.push(smtp);
        for (const f of smtp.findings) allFindings.push({ ...f, hostname: smtp.hostname });
      }
    }
  }

  // IPv6 surface (domain apex + www)
  step('Checking IPv6 surface…');
  const ipv6Targets = [domain, `www.${domain}`];
  for (const target of ipv6Targets) {
    const ipv6 = await checkIPv6Surface(target);
    report.ipv6.push(ipv6);
    for (const f of ipv6.findings) allFindings.push({ ...f, hostname: target });
  }

  const summary = {
    ipsScanned:       uniqueIPs.length,
    openPortsTotal:   report.portScans.reduce((sum, s) => sum + s.openPorts.length, 0),
    criticalPorts:    allFindings.filter(f => f.area === 'port-exposure' && f.severity === 'critical').length,
    sshHostsScanned:  report.sshScans.length,
    sshPQReady:       report.sshScans.filter(s => s.findings.some(f => f.id === 'SSH-PQ-KEX-PRESENT')).length,
    smtpHostsScanned: report.smtpScans.length,
    smtpStartTLS:     report.smtpScans.filter(s => s.starttls).length,
    totalFindings:    allFindings.length,
    bySeverity: {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high:     allFindings.filter(f => f.severity === 'high').length,
      medium:   allFindings.filter(f => f.severity === 'medium').length,
      low:      allFindings.filter(f => f.severity === 'low').length,
      info:     allFindings.filter(f => f.severity === 'info').length,
    },
  };

  return { report, findings: allFindings, summary };
}

module.exports = {
  scanNetworkSecurity,
  portScan,
  probeSSH,
  probeSMTP,
  checkIPv6Surface,
};
