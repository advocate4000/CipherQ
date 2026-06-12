# CipherQ PQC Scanner

**Post-Quantum Cryptographic Domain Scanner**  
Identifies quantum cryptographic vulnerabilities in externally-facing TLS infrastructure.

## What it detects

The scanner covers every finding category from a full Quantum Threat Assessment:

| Finding | Severity | Description |
|---------|----------|-------------|
| No hybrid PQ KEX (X25519MLKEM768) | HIGH | HNDL risk — classical ECDHE is vulnerable to Shor's algorithm |
| PQ KEX status unknown (TLS 1.3) | MEDIUM | Deep enumeration required to confirm KEX group |
| Classical certificate signature (RSA/ECDSA) | MEDIUM | TNFL risk — cert forgeable by a CRQC |
| SNI / certificate mismatch | HIGH | CDN misconfiguration / broken trust signal |
| Deprecated TLS version (1.0/1.1) | CRITICAL | RFC 8996 deprecated; known attack vectors |
| Legacy TLS version accepted | CRITICAL | Downgrade attack surface |
| Weak cipher suite accepted | CRITICAL | RC4, NULL, EXPORT, 3DES |
| TLS 1.2 in use (1.3 preferred) | LOW | Weaker forward secrecy guarantees |
| Certificate expiry < 30 days | MEDIUM/HIGH | Outage risk |
| Certificate EXPIRED | CRITICAL | Immediate outage |
| Dev/staging host in public DNS | HIGH | Information disclosure, exploitation risk |
| Hosting-default subdomain in DNS | MEDIUM | Attack surface / info disclosure |
| Internal platform in public DNS | MEDIUM | Architecture disclosure |
| Remote access service in public DNS | MEDIUM | Targeted attack enablement |
| Monitoring infrastructure exposed | HIGH | Dashboard access, credential risk |
| HTTP not redirecting to HTTPS | MEDIUM | Cleartext traffic possible |

## Standards references

- **NIST FIPS 203** — ML-KEM (Module-Lattice Key Encapsulation Mechanism)
- **NIST FIPS 204** — ML-DSA (Module-Lattice Digital Signature Algorithm)  
- **NIST IR 8547** — Deprecation of RSA-2048/ECC P-256 by 2030, disallowance by 2035
- **IETF draft-ietf-tls-ecdhe-mlkem-05** — X25519MLKEM768 hybrid KEX for TLS 1.3
- **CNSA 2.0** — NSA Commercial National Security Algorithm Suite
- **UK NCSC PQC guidance** — Planning 2028, critical migration 2031, full 2035

## Installation

```bash
npm install
```

Node.js ≥ 18 required.

## CLI Usage

```bash
# Scan a domain (generates ~99 candidate subdomains)
node cli.js example.com

# Scan with specific hosts only
node cli.js example.com --hosts www.example.com,api.example.com,dev.example.com

# JSON output (pipe-friendly)
node cli.js example.com --json

# Save JSON report
node cli.js example.com --json --output report.json

# Fast scan (skip legacy TLS and weak cipher probes)
node cli.js example.com --no-legacy --no-weak-cipher

# Verbose (show per-host progress)
node cli.js example.com --verbose

# Higher concurrency (faster, more aggressive)
node cli.js example.com --concurrency 10
```

Exit code: `0` = no critical findings, `1` = critical findings, `2` = fatal error.

## Web UI / API Server

```bash
node server.js
# Open http://localhost:3000
```

The web UI includes:
- Domain scan with live progress
- Findings table with severity filters
- Host detail table (protocol, cipher, CA, expiry, SNI, PQ status)
- DNS surface enumeration grouped by category
- CA distribution chart
- Automated roadmap (Phase 1/2/3)
- HNDL risk banner

### API endpoints

```
POST /api/scan          Start a scan job
  Body: { domain, customHosts?, deepLegacy?, weakCipher? }
  Returns: { jobId }

GET  /api/scan/:jobId   Poll job status / get results
  Returns: { status, progress?, result? }

POST /api/analyse       Single host analysis
  Body: { hostname, deepLegacy?, weakCipher? }

GET  /api/hosts/:domain List candidate subdomains for a domain
```

## Architecture

```
scanner.js   Core engine: TLS probe, DNS probe, KEX analysis, finding generation
server.js    Express API server + serves web UI
cli.js       CLI with coloured output and progress bar
public/      Web UI (single HTML file, AI-powered via Anthropic API)
```

## Technical notes

### KEX group detection limitation

Node.js's built-in TLS API does not expose the negotiated named group (e.g. X25519 vs X25519MLKEM768) from the standard `socket.getCipher()` or `socket.getPeerCertificate()` calls. Detecting whether a server has hybrid PQ KEX enabled requires either:

1. A deep enumeration tool like `testssl.sh --groups` or `sslyze --tlsv1_3` that tries each named group in isolation
2. OpenSSL's native group negotiation telemetry (not exposed via Node.js bindings)

The scanner correctly flags TLS 1.3 hosts as "classical-likely" based on the mid-2026 industry baseline (hybrid PQ KEX requires explicit enablement in OpenSSL 3.5+/Go 1.24+) and recommends deep enumeration as a P1 action.

### Proxy/CDN interception

In environments behind a TLS-intercepting proxy, certificate metadata (issuer, CN) will reflect the proxy's certificate rather than the target server's. The CA name detection accounts for this by flagging "Anthropic" egress gateway certs appropriately.

### Concurrency and rate limits

Default concurrency is 5 parallel probes. Increase with `--concurrency` for faster scans; decrease if the target enforces rate limits on TCP/443 connections.

## Roadmap (tool development)

- [ ] `testssl.sh` integration for confirmed KEX group enumeration
- [ ] HSTS / HPKP header detection
- [ ] Certificate Transparency log lookup (crt.sh API)  
- [ ] DNSSEC validation status
- [ ] TLSA / DANE record detection
- [ ] SSH host key algorithm detection (port 22)
- [ ] Mail server TLS probes (STARTTLS on port 25/587)
- [ ] PQ KEX detection via raw TLS ClientHello/ServerHello parsing
- [ ] CBOM (Cryptographic Bill of Materials) JSON export (NIST SP 800-53 format)
- [ ] Continuous monitoring mode with alerting
