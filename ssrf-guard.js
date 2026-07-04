'use strict';

/**
 * CipherQ — SSRF Guard
 *
 * Prevents the scanner from being pointed at:
 *   - Loopback / localhost (127.0.0.0/8, ::1)
 *   - RFC-1918 private ranges (10/8, 172.16-31/12, 192.168/16)
 *   - Link-local / APIPA (169.254/16 — includes AWS metadata at 169.254.169.254)
 *   - IPv6 ULA (fc00::/7) and link-local (fe80::/10)
 *   - Unspecified / broadcast (0.0.0.0, 255.255.255.255)
 *   - Multicast (224/4)
 *
 * Call assertScannable(hostname) before any network probe.
 * It resolves the hostname and throws if any IP is private.
 *
 * To fully close the DNS-rebinding window the caller should pin the resolved
 * public IP and connect directly (host= ip, servername= hostname) rather than
 * re-resolving at connect time — see the note in probeTLS.
 */

const net = require('net');
const dns = require('dns').promises;

// Single source of truth for what counts as a private/reserved address.
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return true; // can't parse = block it
  const [a, b] = parts;
  return (
    a === 0                                 ||  // 0.0.0.0/8 — "this network"
    a === 10                                ||  // 10.0.0.0/8 — RFC 1918
    a === 127                               ||  // 127.0.0.0/8 — loopback
    (a === 169 && b === 254)               ||  // 169.254.0.0/16 — link-local / metadata
    (a === 172 && b >= 16 && b <= 31)     ||  // 172.16.0.0/12 — RFC 1918
    (a === 192 && b === 168)              ||  // 192.168.0.0/16 — RFC 1918
    a >= 224                                   // 224.0.0.0/4 — multicast and above
  );
}

function isPrivateIPv6(ip) {
  const x = ip.toLowerCase().replace(/^::ffff:/i, ''); // strip IPv4-mapped prefix first
  // Check if it's now an IPv4 address
  if (net.isIPv4(x)) return isPrivateIPv4(x);

  return (
    x === '::1'             ||  // loopback
    x === '::'              ||  // unspecified
    x.startsWith('fc')      ||  // ULA fc00::/7
    x.startsWith('fd')      ||  // ULA fd00::/7
    x.startsWith('fe80')    ||  // link-local
    x.startsWith('ff')          // multicast
  );
}

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true; // unknown format — block
}

/**
 * Resolve hostname and throw if any resolved IP is private/reserved.
 * Returns the first resolved public IPv4 (for optional IP pinning).
 *
 * @param {string} hostname
 * @param {{ allowPrivate?: boolean }} opts
 * @returns {Promise<string>}  first public IPv4 address
 * @throws if any IP is private, or hostname looks like a direct IP literal
 */
async function assertScannable(hostname, { allowPrivate = false } = {}) {
  if (allowPrivate) return hostname;

  // Reject bare IP literals the UI might pass in
  if (net.isIPv4(hostname)) {
    if (isPrivateIPv4(hostname)) throw new Error(`Blocked: ${hostname} is a private/reserved IPv4 address`);
    return hostname;
  }
  if (net.isIPv6(hostname)) {
    if (isPrivateIPv6(hostname)) throw new Error(`Blocked: ${hostname} is a private/reserved IPv6 address`);
    return hostname;
  }

  // Common metadata / internal hostnames
  const blockedNames = ['localhost', 'metadata', 'instance-data', 'computemetadata'];
  const lower = hostname.toLowerCase().split('.')[0];
  if (blockedNames.includes(lower)) {
    throw new Error(`Blocked: "${hostname}" is a reserved or metadata hostname`);
  }

  // Resolve A and AAAA in parallel
  const [v4, v6] = await Promise.all([
    dns.resolve4(hostname).catch(() => []),
    dns.resolve6(hostname).catch(() => []),
  ]);

  const allIPs = [...v4, ...v6];
  if (allIPs.length === 0) {
    // NXDOMAIN / no resolution — let the scanner handle it gracefully
    return null;
  }

  for (const ip of allIPs) {
    if (isPrivateIP(ip)) {
      throw new Error(
        `SSRF blocked: "${hostname}" resolves to ${ip} which is a private/reserved address`
      );
    }
  }

  return v4[0] || v6[0] || null;
}

module.exports = { assertScannable, isPrivateIP, isPrivateIPv4, isPrivateIPv6 };
