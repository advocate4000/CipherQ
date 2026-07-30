'use strict';

/**
 * CipherQ — SSRF Guard
 *
 * Prevents the scanner from being pointed at:
 *   - Loopback / localhost (127.0.0.0/8, ::1)
 *   - RFC-1918 private ranges (10/8, 172.16-31/12, 192.168/16)
 *   - CGNAT (100.64.0.0/10 — RFC 6598)
 *   - Link-local / APIPA (169.254/16 — includes AWS/GCP/Azure metadata at 169.254.169.254)
 *   - IPv6 ULA (fc00::/7), link-local (fe80::/10), NAT64 (64:ff9b::/96), 6to4 (2002::/16)
 *   - Unspecified / broadcast (0.0.0.0, 255.255.255.255)
 *   - Multicast (224/4 and IPv6 ff00::/8)
 *   - Alternate-form IPv4 literals that encode a private address but don't
 *     match Node's strict dotted-decimal net.isIPv4() — decimal integer
 *     ("2130706433"), octal octets ("0177.0.0.1"), hex octets ("0x7f.0.0.1"),
 *     and inet_aton-style short forms ("127.1"). These are the classic
 *     SSRF-guard bypass class: getaddrinfo() and many HTTP/TLS client stacks
 *     will happily interpret them as an IP literal even though a naive
 *     dotted-decimal regex won't recognise the string as one.
 *
 * Call assertScannable(hostname) before any network probe. It resolves the
 * hostname and throws if any IP is private. On ambiguous/unparseable input
 * it FAILS CLOSED (throws) rather than silently passing through — a prior
 * version returned `null` for "doesn't resolve", which is correct for a
 * genuine NXDOMAIN but was also indistinguishable from "this is a private
 * IP-literal string DNS can't resolve as a hostname", which is exactly the
 * case an attacker controls.
 *
 * To fully close the DNS-rebinding window the caller should pin the resolved
 * public IP and connect directly (host= ip, servername= hostname) rather than
 * re-resolving at connect time — see the note in probeTLS. As of this
 * revision, callers MUST route every probe (TLS, legacy TLS, weak cipher,
 * HTTP) through the pinned IP — see scanner.js.
 */

const net = require('net');
const dns = require('dns').promises;

// ─── Alternate-form IPv4 literal parsing ─────────────────────────────────────
// Mirrors (a conservative subset of) what glibc's inet_aton / getaddrinfo
// will accept: 1-4 dot-separated parts, each parseable as decimal, octal
// (leading 0), or hex (leading 0x), with the last part absorbing the
// remaining bits. Returns a canonical "a.b.c.d" string, or null if the input
// doesn't look like an IP literal in any recognised form (i.e. it's a real
// hostname and should proceed to normal DNS resolution).
function parsePart(part) {
  if (/^0x[0-9a-f]+$/i.test(part)) return parseInt(part, 16);
  if (/^0[0-7]+$/.test(part)) return parseInt(part, 8);
  if (/^0$/.test(part)) return 0;
  if (/^[1-9][0-9]*$/.test(part)) return parseInt(part, 10);
  return null;
}

function canonicaliseIPv4Literal(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 79) return null;
  // Already strict dotted-decimal — nothing to canonicalise.
  if (net.isIPv4(input)) return input;

  const rawParts = input.split('.');
  if (rawParts.length < 1 || rawParts.length > 4) return null;
  if (rawParts.some(p => p === '')) return null;

  const parts = rawParts.map(parsePart);
  if (parts.some(p => p === null || !Number.isFinite(p) || p < 0)) return null;

  let value;
  switch (parts.length) {
    case 1: // a  -> whole 32-bit value
      value = parts[0];
      break;
    case 2: // a.b -> a=8 bits, b=24 bits
      if (parts[0] > 0xff || parts[1] > 0xffffff) return null;
      value = (parts[0] << 24) | parts[1];
      break;
    case 3: // a.b.c -> a=8, b=8, c=16
      if (parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff) return null;
      value = (parts[0] << 24) | (parts[1] << 16) | parts[2];
      break;
    case 4: // a.b.c.d -> standard, but via non-decimal radices
      if (parts.some(p => p > 0xff)) return null;
      value = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
      break;
    default:
      return null;
  }

  if (!Number.isFinite(value) || value < 0 || value > 0xffffffff) return null;
  value = value >>> 0; // force unsigned 32-bit

  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.');
}

// Single source of truth for what counts as a private/reserved IPv4 address.
// Expects a canonical dotted-decimal string (net.isIPv4-valid).
function isPrivateIPv4Canonical(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return true; // can't parse = block it
  const [a, b] = parts;
  return (
    a === 0                                ||  // 0.0.0.0/8 — "this network"
    a === 10                               ||  // 10.0.0.0/8 — RFC 1918
    a === 127                              ||  // 127.0.0.0/8 — loopback
    (a === 100 && b >= 64 && b <= 127)     ||  // 100.64.0.0/10 — CGNAT (RFC 6598)
    (a === 169 && b === 254)               ||  // 169.254.0.0/16 — link-local / cloud metadata
    (a === 172 && b >= 16 && b <= 31)      ||  // 172.16.0.0/12 — RFC 1918
    (a === 192 && b === 168)               ||  // 192.168.0.0/16 — RFC 1918
    a >= 224                                   // 224.0.0.0/4 multicast, and reserved 240+/broadcast
  );
}

// Public entry point: accepts ANY string form (strict dotted-decimal,
// decimal integer, octal, hex, short forms) and returns whether it's private.
// Returns true (blocked) if the string can't be canonicalised at all AND
// looks IP-literal-shaped (all-numeric/hex/octal parts) — genuine hostnames
// containing letters never reach canonicaliseIPv4Literal's accepted patterns
// so they're unaffected.
function isPrivateIPv4(ip) {
  const canon = canonicaliseIPv4Literal(ip);
  if (canon === null) return true; // couldn't parse as IPv4 at all — caller should not treat this as a usable IPv4
  return isPrivateIPv4Canonical(canon);
}

// ─── IPv6 ─────────────────────────────────────────────────────────────────────

function ipv6ToBytes(ip) {
  // Node's own parser is the source of truth for validity; reject anything
  // it doesn't accept as IPv6 before attempting to expand it ourselves.
  if (!net.isIPv6(ip)) return null;
  try {
    // Uses Node's internal-safe path: round-trip through the address family
    // aware URL host parser is unnecessary — a small manual expander suffices
    // since net.isIPv6 already validated the string.
    let [head, tail] = ip.split('::');
    let headParts = head ? head.split(':') : [];
    let tailParts = tail ? tail.split(':') : [];
    // Handle IPv4-mapped tail (e.g. ::ffff:127.0.0.1)
    const last = tailParts[tailParts.length - 1] || headParts[headParts.length - 1];
    if (last && last.includes('.')) {
      const v4canon = canonicaliseIPv4Literal(last);
      if (v4canon) {
        const v4parts = v4canon.split('.').map(Number);
        const hex1 = ((v4parts[0] << 8) | v4parts[1]).toString(16);
        const hex2 = ((v4parts[2] << 8) | v4parts[3]).toString(16);
        if (tailParts.length && tailParts[tailParts.length - 1] === last) {
          tailParts = [...tailParts.slice(0, -1), hex1, hex2];
        } else if (headParts.length && headParts[headParts.length - 1] === last) {
          headParts = [...headParts.slice(0, -1), hex1, hex2];
        }
      }
    }
    if (ip.includes('::')) {
      const missing = 8 - (headParts.length + tailParts.length);
      const zeros = new Array(Math.max(0, missing)).fill('0');
      headParts = [...headParts, ...zeros, ...tailParts];
    }
    const full = headParts.length === 8 ? headParts : ip.split(':');
    const bytes = [];
    for (const group of full) {
      const v = parseInt(group || '0', 16);
      bytes.push((v >>> 8) & 0xff, v & 0xff);
    }
    return bytes.length === 16 ? bytes : null;
  } catch {
    return null;
  }
}

function isPrivateIPv6(ip) {
  const x = ip.toLowerCase().replace(/^::ffff:/i, ''); // strip IPv4-mapped prefix first
  if (net.isIPv4(x) || canonicaliseIPv4Literal(x)) return isPrivateIPv4(x);

  if (
    x === '::1'             ||  // loopback
    x === '::'              ||  // unspecified
    x.startsWith('fc')      ||  // ULA fc00::/7
    x.startsWith('fd')      ||  // ULA fd00::/7
    x.startsWith('fe80')    ||  // link-local
    x.startsWith('ff')          // multicast ff00::/8
  ) return true;

  // NAT64 well-known prefix 64:ff9b::/96 — embeds an IPv4 address in the
  // last 32 bits. 64:ff9b::7f00:1 is 127.0.0.1 reached via a NAT64 gateway.
  if (x.startsWith('64:ff9b::') || x.startsWith('64:ff9b:0:0:0:0:')) {
    const bytes = ipv6ToBytes(x);
    if (bytes) {
      const embeddedV4 = bytes.slice(12).join('.');
      if (isPrivateIPv4Canonical(embeddedV4)) return true;
    }
  }

  // 6to4 2002::/16 — embeds an IPv4 address directly after the 2002: prefix.
  if (x.startsWith('2002:')) {
    const bytes = ipv6ToBytes(x);
    if (bytes) {
      const embeddedV4 = bytes.slice(2, 6).join('.');
      if (isPrivateIPv4Canonical(embeddedV4)) return true;
    }
  }

  return false;
}

function isPrivateIP(ip) {
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  if (net.isIPv4(ip) || canonicaliseIPv4Literal(ip)) return isPrivateIPv4(ip);
  return true; // unknown format — block
}

/**
 * Synchronous, no-network checks: is this hostname string itself an IP
 * literal (in ANY form) in a private range, or a known metadata/reserved
 * name? Split out from assertScannable so callers that already have their
 * own resolved DNS records (e.g. scanner.js's analyseHost, which calls
 * probeDNS separately) can reuse this cheap check per-host without forcing
 * a second, independent DNS resolution for every host in a scan.
 *
 * @returns {{ blocked: boolean, reason: string|null, canonicalIP: string|null }}
 */
function checkHostnameLiteral(hostname) {
  if (typeof hostname !== 'string' || hostname.trim() === '') {
    return { blocked: true, reason: 'empty or invalid hostname', canonicalIP: null };
  }

  if (net.isIPv6(hostname)) {
    if (isPrivateIPv6(hostname)) {
      return { blocked: true, reason: `${hostname} is a private/reserved IPv6 address`, canonicalIP: null };
    }
    return { blocked: false, reason: null, canonicalIP: hostname };
  }

  const v4Literal = canonicaliseIPv4Literal(hostname);
  if (v4Literal !== null) {
    if (isPrivateIPv4Canonical(v4Literal)) {
      return { blocked: true, reason: `"${hostname}" is an IP literal (canonical form ${v4Literal}) in a private/reserved range`, canonicalIP: v4Literal };
    }
    return { blocked: false, reason: null, canonicalIP: v4Literal };
  }

  const blockedNames = ['localhost', 'metadata', 'instance-data', 'computemetadata'];
  const lower = hostname.toLowerCase().split('.')[0];
  if (blockedNames.includes(lower)) {
    return { blocked: true, reason: `"${hostname}" is a reserved or metadata hostname`, canonicalIP: null };
  }

  return { blocked: false, reason: null, canonicalIP: null }; // genuine hostname — needs DNS resolution
}

/**
 * Check a set of already-resolved IPs (from a DNS lookup the caller already
 * performed) against the private/reserved ranges. Use this instead of
 * calling assertScannable a second time when you already have the records —
 * e.g. from probeDNS() — to avoid a duplicate DNS round-trip per host and to
 * avoid a TOCTOU window between two independent resolves of the same name.
 *
 * @returns {{ blocked: boolean, reason: string|null }}
 */
function checkResolvedIPs(ips) {
  for (const ip of ips || []) {
    if (isPrivateIP(ip)) {
      return { blocked: true, reason: `resolves to ${ip} which is a private/reserved address` };
    }
  }
  return { blocked: false, reason: null };
}

/**
 * Resolve hostname and throw if any resolved IP is private/reserved.
 * Returns the first resolved public IPv4 (for optional IP pinning).
 *
 * FAILS CLOSED: any ambiguity (unparseable IP-literal-shaped input, or a
 * hostname that resolves to zero addresses) throws rather than passing a
 * `null` the caller might treat as "safe to proceed".
 *
 * @param {string} hostname
 * @param {{ allowPrivate?: boolean }} opts
 * @returns {Promise<string>}  first public IPv4 address
 * @throws if any IP is private, or hostname looks like a direct IP literal
 *         (in ANY form — dotted-decimal, decimal, octal, or hex), or if the
 *         hostname does not resolve at all.
 */
async function assertScannable(hostname, { allowPrivate = false } = {}) {
  if (allowPrivate) return hostname;

  const literalCheck = checkHostnameLiteral(hostname);
  if (literalCheck.blocked) throw new Error(`Blocked: ${literalCheck.reason}`);
  if (literalCheck.canonicalIP) return literalCheck.canonicalIP; // was an IP literal, already validated public

  // Resolve A and AAAA in parallel
  const [v4, v6] = await Promise.all([
    dns.resolve4(hostname).catch(() => []),
    dns.resolve6(hostname).catch(() => []),
  ]);

  const allIPs = [...v4, ...v6];
  if (allIPs.length === 0) {
    // Genuine NXDOMAIN for a real hostname (we've already ruled out this
    // being an IP-literal-shaped string above) — nothing will be connected
    // to, so this is safe to report as "not resolvable" rather than blocked.
    // The scanner's NXDOMAIN early-exit handles this gracefully.
    return null;
  }

  const resolvedCheck = checkResolvedIPs(allIPs);
  if (resolvedCheck.blocked) {
    throw new Error(`SSRF blocked: "${hostname}" ${resolvedCheck.reason}`);
  }

  return v4[0] || v6[0] || null;
}

module.exports = {
  assertScannable,
  isPrivateIP,
  isPrivateIPv4,
  isPrivateIPv6,
  canonicaliseIPv4Literal,
  checkHostnameLiteral,
  checkResolvedIPs,
};
