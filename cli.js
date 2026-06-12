#!/usr/bin/env node
'use strict';

/**
 * CipherQ PQC Scanner — CLI
 * Usage: node cli.js <domain> [options]
 *
 * Options:
 *   --hosts host1,host2     Custom host list (comma-separated)
 *   --no-legacy             Skip TLS 1.0/1.1 probes
 *   --no-weak-cipher        Skip weak cipher probes
 *   --json                  Output raw JSON
 *   --output <file>         Save JSON report to file
 *   --concurrency <n>       Parallel probe concurrency (default: 5)
 */

const { scanDomain, analyseHost } = require('./scanner');
const fs = require('fs');

// ─── Colour helpers ───────────────────────────────────────────────────────────
const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  green:  '\x1b[32m',
  cyan:   '\x1b[36m',
  blue:   '\x1b[34m',
  magenta:'\x1b[35m',
  white:  '\x1b[97m',
  grey:   '\x1b[90m',
};

const SEV_COLOUR = {
  critical: C.red,
  high:     C.yellow,
  medium:   C.cyan,
  low:      C.blue,
  info:     C.grey,
};

function c(colour, str) {
  if (process.env.NO_COLOR || !process.stdout.isTTY) return str;
  return `${colour}${str}${C.reset}`;
}

function header(title) {
  const line = '─'.repeat(70);
  console.log(c(C.grey, `\n${line}`));
  console.log(c(C.bold + C.white, ` ${title}`));
  console.log(c(C.grey, line));
}

function printBanner() {
  console.log(c(C.cyan + C.bold, `
  ╔═══════════════════════════════════════════════════════╗
  ║  CipherQ PQC Scanner — Quantum Threat Assessment CLI  ║
  ║  NIST FIPS 203/204 · IETF draft-ietf-tls-ecdhe-mlkem ║
  ╚═══════════════════════════════════════════════════════╝
`));
}

function sevLabel(sev) {
  const col = SEV_COLOUR[sev] || C.grey;
  return c(col, `[${sev.toUpperCase().padEnd(8)}]`);
}

function pqBadge(status) {
  switch (status) {
    case 'none':           return c(C.red,    '✗ NONE   ');
    case 'unknown':        return c(C.yellow, '? UNKNOWN');
    case 'partial':        return c(C.cyan,   '~ PARTIAL');
    case 'ready':          return c(C.green,  '✓ READY  ');
    case 'not-applicable': return c(C.grey,   '  N/A    ');
    default:               return c(C.grey,   '  —      ');
  }
}

function riskBadge(risk) {
  switch (risk) {
    case 'high':           return c(C.red,    'HIGH        ');
    case 'high-likely':    return c(C.red,    'HIGH (LIKELY)');
    case 'mitigated':      return c(C.green,  'MITIGATED   ');
    case 'not-applicable': return c(C.grey,   'N/A         ');
    default:               return c(C.grey,   'UNKNOWN     ');
  }
}

// ─── Parse args ───────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    domain: null,
    hosts: [],
    deepLegacy: true,
    weakCipher: true,
    jsonOutput: false,
    outputFile: null,
    concurrency: 5,
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') { opts.jsonOutput = true; continue; }
    if (a === '--no-legacy') { opts.deepLegacy = false; continue; }
    if (a === '--no-weak-cipher') { opts.weakCipher = false; continue; }
    if (a === '--verbose') { opts.verbose = true; continue; }
    if (a === '--hosts') { opts.hosts = args[++i].split(',').map(s => s.trim()); continue; }
    if (a === '--output') { opts.outputFile = args[++i]; continue; }
    if (a === '--concurrency') { opts.concurrency = parseInt(args[++i], 10); continue; }
    if (!a.startsWith('--')) opts.domain = a;
  }

  return opts;
}

function usage() {
  console.log(`
${c(C.bold, 'Usage:')} node cli.js <domain> [options]

${c(C.bold, 'Options:')}
  --hosts h1,h2        Custom host list (comma-separated)
  --no-legacy          Skip TLS 1.0/1.1 downgrade probes
  --no-weak-cipher     Skip weak cipher suite probes
  --json               Output raw JSON report
  --output <file>      Save JSON to file
  --concurrency <n>    Parallel concurrency (default: 5)
  --verbose            Show per-host progress

${c(C.bold, 'Examples:')}
  node cli.js example.com
  node cli.js example.com --json --output report.json
  node cli.js example.com --hosts www.example.com,api.example.com
  node cli.js example.com --no-legacy --concurrency 10
`);
}

// ─── Render text report ───────────────────────────────────────────────────────
function printTextReport(result) {
  const { summary, hosts, findings } = result;

  printBanner();

  // ── Executive summary ─────────────────────────────────────────────────────
  header('QUANTUM THREAT ASSESSMENT SUMMARY');

  console.log(`
  Domain:              ${c(C.white, summary.domain)}
  Scan completed:      ${summary.scanTime}
  Hosts probed:        ${c(C.white, summary.hostsProbed)}
  Hosts reachable:     ${c(C.white, summary.hostsReachable)}
  Hosts unreachable:   ${c(C.grey, summary.hostsUnreachable)} (DNS resolves, no TLS)
  `);

  // Risk overview
  const sev = summary.findingsBySeverity;
  console.log(c(C.bold, '  Findings by severity:'));
  const sevOrder = ['critical','high','medium','low','info'];
  for (const s of sevOrder) {
    if (sev[s] > 0) {
      console.log(`    ${sevLabel(s)} ${sev[s]} finding${sev[s] !== 1 ? 's' : ''}`);
    }
  }

  // HNDL risk
  const hndlCol = summary.overallHndlRisk.startsWith('high') ? C.red : C.yellow;
  console.log(`\n  ${c(C.bold, 'HNDL Risk (Harvest-Now-Decrypt-Later):')} ${c(hndlCol + C.bold, summary.overallHndlRisk.toUpperCase())}`);
  if (summary.overallHndlRisk.startsWith('high')) {
    console.log(c(C.grey, `  ↳ No hybrid post-quantum key exchange detected on any reachable host.`));
    console.log(c(C.grey, `    Session traffic recorded today is decryptable by a future CRQC.`));
  }

  // PQ readiness
  console.log(`\n  ${c(C.bold, 'PQ Readiness breakdown:')}  ` +
    `NONE: ${c(C.red, summary.pqReadinessBreakdown.none)}  ` +
    `UNKNOWN: ${c(C.yellow, summary.pqReadinessBreakdown.unknown)}  ` +
    `PARTIAL: ${c(C.cyan, summary.pqReadinessBreakdown.partial)}  ` +
    `READY: ${c(C.green, summary.pqReadinessBreakdown.ready)}`);

  if (summary.sniMismatches.length > 0) {
    console.log(`\n  ${c(C.bold + C.yellow, 'SNI mismatches:')} ${summary.sniMismatches.join(', ')}`);
  }

  if (summary.devHostsExposed.length > 0) {
    console.log(`  ${c(C.bold + C.red, 'Dev hosts exposed:')} ${summary.devHostsExposed.join(', ')}`);
  }

  // ── Reachable hosts table ─────────────────────────────────────────────────
  header('REACHABLE HOSTS');

  const reachable = hosts.filter(h => h.tls?.cipher);
  if (reachable.length === 0) {
    console.log(c(C.grey, '  No hosts completed a TLS handshake.\n'));
  } else {
    const colW = [40, 9, 10, 8, 12, 10];
    const cols = ['Hostname', 'Protocol', 'PQ-Ready', 'HNDL', 'Cert Expiry', 'CA'];
    const fmt = (vals) => vals.map((v, i) => v.padEnd ? v.padEnd(colW[i]) : String(v).padEnd(colW[i])).join('  ');

    console.log(c(C.grey, '  ' + fmt(cols)));
    console.log(c(C.grey, '  ' + '─'.repeat(colW.reduce((a,b) => a+b+2, 0))));

    for (const h of reachable) {
      const days = h.tls?.certDaysToExpiry;
      const daysStr = days !== null && days !== undefined ? `${days}d` : '—';
      const dayCol = days !== null && days < 14 ? C.red : days !== null && days < 30 ? C.yellow : C.green;
      const ca = (h.tls?.caName || '—').slice(0, 18);
      const hn = h.hostname.slice(0, 38);

      console.log('  ' +
        hn.padEnd(colW[0]) + '  ' +
        (h.tls?.protocol || '—').padEnd(colW[1]) + '  ' +
        pqBadge(h.pqReadiness) + '  ' +
        riskBadge(h.hndlRisk) + '  ' +
        c(dayCol, daysStr.padEnd(colW[4])) + '  ' +
        c(C.grey, ca)
      );
    }
    console.log();
  }

  // ── Findings ──────────────────────────────────────────────────────────────
  header('SECURITY FINDINGS');

  const order = ['critical','high','medium','low','info'];
  const sorted = [...findings].sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  if (sorted.length === 0) {
    console.log(c(C.green, '  ✓ No findings.\n'));
  }

  for (const f of sorted) {
    console.log(`\n  ${sevLabel(f.severity)} ${c(C.bold, f.title)}`);
    if (f.hostname) console.log(`           Host: ${c(C.cyan, f.hostname)}`);
    console.log(c(C.grey, `           ${f.detail.replace(/\n/g, '\n           ')}`));
    if (f.recommendation) {
      console.log(c(C.green, `           → ${f.recommendation}`));
    }
    if (f.nistRef) {
      console.log(c(C.grey, `           NIST: ${f.nistRef}`));
    }
    if (f.priority) {
      console.log(c(C.yellow, `           Priority: ${f.priority}`));
    }
  }

  // ── DNS surface ───────────────────────────────────────────────────────────
  header('DNS SURFACE');

  const unreachable = hosts.filter(h => h.dns?.resolves && !h.tls?.cipher);
  const nxdomain = hosts.filter(h => !h.dns?.resolves);

  if (reachable.length > 0) {
    console.log(`\n  ${c(C.green, 'Reachable (TLS):')}  ${reachable.map(h => c(C.white, h.hostname)).join(', ')}`);
  }
  if (unreachable.length > 0) {
    console.log(`  ${c(C.yellow, 'DNS only (no TLS):')} ${unreachable.map(h => h.hostname).join(', ')}`);
  }
  if (nxdomain.length > 0) {
    console.log(`  ${c(C.grey, 'NXDOMAIN:')}          ${nxdomain.slice(0,10).map(h => h.hostname).join(', ')}${nxdomain.length > 10 ? '...' : ''}`);
  }

  // ── Roadmap ───────────────────────────────────────────────────────────────
  header('RECOMMENDED ROADMAP');
  console.log(`
  ${c(C.yellow + C.bold, 'Phase 1 (0–6 months)')} — Inventory & Configure
    → Appoint named owner for public cryptographic posture
    → Run deep TLS enumeration (testssl.sh --groups) to confirm KEX groups
    → Build Cryptographic Bill of Materials (CBOM)
    → Resolve SNI mismatches and restrict exposed dev infrastructure
    → Engage CDN/hosting providers on hybrid PQ TLS roadmap

  ${c(C.cyan + C.bold, 'Phase 2 (6–18 months)')} — Enable & Retire
    → Enable hybrid PQ KEX (X25519MLKEM768) — OpenSSL 3.5+, Go 1.24+
    → Prune dormant DNS entries; migrate dev environments to private posture
    → Publish public-facing quantum-readiness statement

  ${c(C.green + C.bold, 'Phase 3 (18+ months)')} — Adopt & Harden
    → Adopt ML-DSA (FIPS 204) leaf certificates as CAs offer them (2027+)
    → Review and re-encrypt long-term archived sensitive communications
    → Extend CBOM to internal infrastructure and SaaS dependencies

  ${c(C.grey, 'Regulatory horizon: NIST IR 8547 deprecates RSA-2048/ECC P-256 by 2030.')}
  ${c(C.grey, 'CNSA 2.0 acquisition mandate: Jan 2027. UK NCSC critical migration: 2031.')}
`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const opts = parseArgs(process.argv);

  if (!opts.domain) {
    printBanner();
    usage();
    process.exit(1);
  }

  if (!opts.jsonOutput) printBanner();

  console.error(c(C.cyan, `Starting PQC scan of ${opts.domain}…`));

  let progress = { completed: 0, total: 0, timer: null };

  const result = await scanDomain(opts.domain, {
    customHosts: opts.hosts,
    deepLegacyProbe: opts.deepLegacy,
    weakCipherProbe: opts.weakCipher,
    concurrency: opts.concurrency,
    onProgress: ({ completed, total, latest }) => {
      progress.completed = completed;
      progress.total = total;

      if (opts.verbose && latest) {
        for (const h of latest) {
          const reachable = h.tls?.cipher ? '✓' : '—';
          const pq = h.pqReadiness;
          process.stderr.write(c(C.grey, `  [${reachable}] ${h.hostname} — PQ: ${pq}\n`));
        }
      } else {
        process.stderr.write(
          `\r${c(C.cyan, `  Probing: ${completed}/${total}`)}` +
          ` ${'█'.repeat(Math.floor((completed/Math.max(total,1))*30)).padEnd(30,'░')}`
        );
      }
    },
  });

  process.stderr.write('\n');

  if (opts.outputFile) {
    fs.writeFileSync(opts.outputFile, JSON.stringify(result, null, 2), 'utf8');
    console.error(c(C.green, `  Report saved to ${opts.outputFile}`));
  }

  if (opts.jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printTextReport(result);
  }

  // Exit code: 1 if any critical findings, 0 otherwise
  const criticals = result.findings.filter(f => f.severity === 'critical').length;
  process.exit(criticals > 0 ? 1 : 0);
}

main().catch(e => {
  console.error(c(C.red, `Fatal error: ${e.message}`));
  process.exit(2);
});
