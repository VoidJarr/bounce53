# bounce53

**DNS Relay Exfiltration Assessment Tool** by VoidJarr

For authorized penetration testing use only.

Tests a corporate DNS resolver for susceptibility to DNS-based data exfiltration / relay abuse using a linear seven-test model (T1–T7):

- **T1** — External relay viability (UDP + TCP)
- **T2** — Record type coverage (UDP full set; TCP limited to A+TXT)
- **T3** — Label length tolerance + qname minimization advisory
- **T4** — High-entropy / IDS pattern tolerance
- **T5** — Response payload capacity (TXT + EDNS probes, truncation, TCP fallback)
- **T6** — Rate limiting (30-query burst + optional ~90-query sustained at ~1 QPS)
- **T7** — Direct egress bypass (UDP/53, TCP/53, DoH, best-effort DoT)

Results include per-transport details, explicit OOB verification labels for heuristic tests, and actionable remediation. TCP is on by default with nested `transport.udp` / `transport.tcp` results. Use `--udp-only` for quieter runs.

***

## Legal Notice

This tool must only be used against systems you own or have explicit written authorization to test. Unauthorized use against third-party infrastructure may constitute a criminal offense under applicable cybercrime legislation.

***

## Requirements

- Python 3.6+
- `dig` (part of `dnsutils` / `bind-utils`)
- An OOB domain you control with an authoritative nameserver (your attack box) — required for T3/T4 confirmation

```bash
# Debian / Kali
sudo apt install dnsutils

# RHEL / CentOS / Fedora
sudo dnf install bind-utils
```

No Python dependencies beyond the standard library.

***

## Quick Start

```bash
# Clone / copy the script
chmod +x bounce53.py

# Minimum required arguments
python3 bounce53.py -r 10.0.0.53 -d oob.attacker.com

# Full example with custom output and timeout
python3 bounce53.py -r 10.0.0.53 -d oob.pentest.io \
    -o /tmp/client-dns-report -f json \
    --timeout 8

# Quiet mode (lower footprint — skips T4 entropy, T7 bypass, and T6 rate-limit burst)
python3 bounce53.py -r 10.0.0.53 -d oob.pentest.io \
    --skip-ratelimit --skip-entropy --skip-bypass

# TCP is on by default for T1–T6 and T5 (response). Use --udp-only for reduced noise / query volume.
python3 bounce53.py -r 10.0.0.53 -d oob.pentest.io --udp-only

# Opt-in sustained low-and-slow rate test (after burst)
python3 bounce53.py -r 10.0.0.53 -d oob.pentest.io --stealth-rate

# Pipe-safe output (no ANSI codes)
python3 bounce53.py -r 10.0.0.53 -d oob.pentest.io --no-color > output.txt
```

### Recommended: Monitor Your OOB NS in a Second Terminal

For T3 (label length) and T4 (entropy) results to be conclusive, watch your authoritative nameserver for incoming queries:

```bash
# On your OOB NS / attack server
sudo tcpdump -i any -n port 53

# Or via BIND query log
tail -f /var/log/named/queries.log
```

A query arriving at your NS confirms the label passed through the corporate relay — even if the resolver returns NXDOMAIN locally.

***

## Arguments

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-r`, `--resolver` | ✅ Yes | — | Target corporate DNS resolver IP |
| `-d`, `--oob-domain` | ✅ Yes | — | OOB domain you control (NS must point to your server) |
| `-o`, `--output` | No | `bounce53_report` | Base name for output file(s) (no extension) |
| `-f`, `--format` | No | `txt` | Comma-separated output formats (`txt`, `json`). Default `txt` only. |
| `--timeout` | No | `5` | Per-query timeout in seconds |
| `--skip-ratelimit` | No | off | Skip T6 — omits 30-query concurrent burst, reduces footprint |
| `--skip-entropy` | No | off | Skip T4 — avoids sending high-entropy encoded subdomains |
| `--skip-bypass` | No | off | Skip T7 — avoids direct egress probes to 8.8.8.8/1.1.1.1/9.9.9.9 and DoH/DoT |
| `--no-color` | No | off | Disable ANSI color output (safe for piping and logging) |
| `--no-raw` | No | off | Omit raw dig command/output details from the JSON report (smaller files) |
| `--udp-only` | No | off | Disable TCP sub-probes (T1–T6 + T5 response capacity). TCP is on by default with nested `transport.udp` / `transport.tcp` results. |
| `--stealth-rate` | No | off | Enable T6 sustained phase (~90 queries at ~1 QPS) after the burst. Opt-in; adds ~90s. |
| `--skip-doh-dot` | No | off | Skip DoH/DoT sub-checks in T7 (UDP/53 + TCP/53 still run). |
| `--sleep` | No | 0.5 | Seconds to sleep between tests (default 0.5; use 0 for fast runs). |

### Transport (UDP + TCP) — default on

TCP is a first-class sub-dimension. By default (unless `--udp-only`), T1, T2, T3, T4, T5 (response capacity), and T6 run over both UDP and TCP. Results are reported under a nested `transport` object:

```json
"T1_external_relay": {
  "severity": "HIGH",
  "finding": "...",
  "transport": {
    "udp": { "vulnerable": true, "detail": "..." },
    "tcp": { "vulnerable": true, "detail": "..." }
  }
}
```

Overall test severity takes the worst across the two transports (when both run). `--udp-only` produces `{"skipped": true, "reason": "udp-only"}` for the TCP leg and reduces query volume/noise.

T7 (direct egress) always attempts UDP/53 + TCP/53; DoH/DoT are included unless `--skip-doh-dot`.

***

## Test Coverage (T1–T7)

**T1 — External Relay Viability**
Tests whether the resolver will forward queries for external names (google.com + t1-relay.<oob>). UDP + TCP by default.
**Severity (if either leg relays):** HIGH

**T2 — Record Type Coverage**
Tests A/TXT/MX/CNAME/NS/AAAA over UDP (full set) and A+TXT over TCP. TXT is the highest-risk type for high-bandwidth exfil.
**Severity (if TXT relays over UDP):** HIGH

**T3 — Query Payload: Label Length**
Tests 30/45/60/63-char labels. Reports `max_passing_chars` and `per_label_results` per transport. Includes `qname_minimization_risk: "unknown"`.
**OOB verification required** (exact long labels are printed for easy log searching).
**Severity (60+ "pass"):** HIGH (heuristic)

**T4 — Query Payload: Entropy / IDS**
Tests three specific high-entropy patterns + a low-entropy baseline. Baseline failure downgrades severity.
**OOB verification required** (exact pattern labels printed).
**Severity (0 patterns blocked):** HIGH (heuristic)

**T5 — Response Payload Capacity**
Measures TXT response size from the OOB payload record (or google.com fallback) plus EDNS buffer-size probes (512/1232/4096), truncation detection, and TCP fallback when `TC` is seen.
**Severity:** scales on observed TXT length (≥200 = HIGH, ≥50 = MEDIUM).

**T6 — Rate Limiting & Sustained Throughput**
30-query concurrent burst (UDP + TCP). Optional `--stealth-rate` adds a ~90-query ~1 QPS sustained phase with success rate and duration stats.
**Severity (no limiting on burst):** HIGH

**T7 — Direct DNS Egress Bypass**
Tests direct reachability from the assessment host to public resolvers over UDP/53, TCP/53, DoH (Cloudflare + Google), and best-effort DoT. `--skip-doh-dot` skips encrypted paths.
**Severity (any path reachable):** CRITICAL
**Strong caveat:** results reflect only the machine running the tool. Re-test from representative internal hosts.

***

## Output

By default, only a `.txt` report is produced from the `--output` base path (default `bounce53_report`).

Use `-f json` (or `-f txt,json`) to also generate the machine-readable JSON report, which includes findings, transport details, `raw_queries` (unless `--no-raw`), `limitations_and_caveats`, and remediation.

The TXT report uses the same concise, aligned formatting as the live terminal (including OOB Check labels for T3/T4/T6).

Use `--no-raw` for smaller JSON files when you don't need the full dig traces.

***

## Severity Ratings

| Rating | Meaning |
|--------|---------|
| `CRITICAL` | Direct external DNS bypass open — filtering completely absent |
| `HIGH` | Relay open, TXT/long labels pass, no rate limiting — full exfil tool suite viable |
| `MEDIUM` | Partial relay (A-only), soft rate limiting, or partial entropy blocking |
| `LOW` | Controls present but incomplete — limited residual risk |
| `NONE` | Test passed / control effective |

Overall severity reflects the single worst finding across all tests.

***

## Accuracy & Verification

T3 and T4 rely on resolver RCODE heuristics (NXDOMAIN/NOERROR for non-existent subdomains). These responses are frequently synthesized by RPZ, security products, firewalls, or the resolver itself — they do **not** prove the query reached the authoritative server.

T7 measures only the assessment host's direct egress. Compromised internal hosts almost always face stricter controls.

**Always** cross the `raw_queries` (or the explicit OOB check labels printed for T3/T4/T6) against real OOB/authoritative logs for ground truth. The tool surfaces the exact names/patterns you should search for.

These points (and more) are included in every generated report under the LIMITATIONS & CAVEATS section.

***

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Application Layer Protocol: DNS | T1071.004 | Command and Control |
| Exfiltration Over Alternative Protocol | T1048.003 | Exfiltration |

***

## Remediation Reference

The JSON report includes the following remediation guidance:

| Priority | Remediation |
|----------|-------------|
| **Immediate** | Restrict recursion to internal subnets only: `allow-recursion { 10.0.0.0/8; };` in BIND |
| **Short-term** | Block outbound UDP/TCP 53 from all hosts except designated resolvers at the perimeter firewall |
| **Medium-term** | Deploy DNS query logging with entropy anomaly alerting (Zeek + Suricata DNS ruleset) |
| **Strategic** | Implement split DNS with hardened forwarder; deploy RPZ sinkholing; block DoH bypass to 1.1.1.1/8.8.8.8 |

> Note: A hardened DNS forwarder reduces and monitors relay abuse but cannot prevent the relay channel entirely, as forwarding external queries is its core function. Whitelist-only RPZ (permit only pre-approved domains) or a protective DNS service (Cisco Umbrella, Cloudflare Gateway) are the closest approaches to genuine prevention.

***

## Example Terminal Output

```
./bounce53.py -r 10.0.0.53 -d somestring.oastify.com

  ▗▖    ▄▄▄  █  ▐▌▄▄▄▄  ▗▞▀▘▗▞▀▚▖▄▄▄▄ ▄▄▄▄
  ▐▌   █   █ ▀▄▄▞▘█   █ ▝▚▄▖▐▛▀▀▘█       █
  ▐▛▀▚▖▀▄▄▄▀      █   █     ▝▚▄▄▖▀▀▀█ ▀▀▀█
  ▐▙▄▞▘                          ▄▄▄█ ▄▄▄█

                               by VoidJarr

  [INFO] Target: 10.0.0.53  |  OOB: somestring.oastify.com  |  Timeout: 5s  |  Output: bounce53_report  |  TCP: enabled
  [INFO] Capture OOB traffic or check dashboard.

T1 — External Relay Viability
  [PASS] UDP google.com + t1-relay.somestring.oastify.com → answer(s) received
  [PASS] TCP google.com + t1-relay.somestring.oastify.com → answer(s) received

T2 — Record Type Coverage
  [PASS] UDP relayed: A, TXT, MX, CNAME, NS, AAAA
  [PASS] TCP (A+TXT only) relayed: A, TXT

T3 — Query Payload: Label Length
  [PASS] UDP 30-char label  (baseline) → resolver returned NXDOMAIN/NOERROR (heuristic)
  [PASS] UDP 45-char label  (medium exfil chunk) → resolver returned NXDOMAIN/NOERROR (heuristic)
  [PASS] UDP 60-char label  (typical dnscat2/DNSExfil) → resolver returned NXDOMAIN/NOERROR (heuristic)
  [PASS] UDP 63-char label  (DNS spec maximum) → resolver returned NXDOMAIN/NOERROR (heuristic)
  [INFO] UDP max passing chars: 63
  [PASS] TCP max passing chars: 63
  [INFO] OOB check: 60-char: ifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau.somestring.oastify.com
                    63-char: ifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqk.somestring.oastify.com

T4 — Query Payload: Entropy / IDS
  [INFO] UDP baseline reached: True
  [PASS] UDP base32 encoded  (repeating pattern, 40 chars) → reached auth NS
  [PASS] UDP base32 encoded  (random bytes, max entropy, 40 chars) → reached auth NS
  [PASS] UDP hex encoded     (32-char hex string) → reached auth NS
  [INFO] UDP patterns blocked: 0/3
  [INFO] TCP baseline reached: True
  [PASS] TCP base32 encoded  (repeating pattern, 40 chars) → reached auth NS
  [PASS] TCP base32 encoded  (random bytes, max entropy, 40 chars) → reached auth NS
  [PASS] TCP hex encoded     (32-char hex string) → reached auth NS
  [INFO] TCP patterns blocked: 0/3
  [INFO] OOB check: ifaucqkbifaucqkbifaucqkbifaucqkbifaucqkb-t4b32rep.somestring.oastify.com
                    boczlovsix25lymp4366yts2iik3juvlopv35w5j-t4b32rnd.somestring.oastify.com
                    4f3a9c2b7e1d6f8a0b5c9d3e7f2a4b6c-t4hex.somestring.oastify.com

T5 — Response Payload Capacity
  [PASS] UDP TXT payload → 66 chars via t7-payload.somestring.oastify.com
  [PASS] TCP TXT payload → 66 chars via t7-payload.somestring.oastify.com

T6 — Rate Limiting & Sustained Throughput
  [INFO] UDP burst: 30/30 @ 11.6 QPS (2.6s)
  [INFO] TCP burst: 30/30 @ 11.4 QPS (2.6s)
  [WARN] No rate limiting detected — 30/30 resolved at 11.6 QPS (UDP burst)
  [INFO] OOB check: *.t6-ratelimit.somestring.oastify.com

T7 — Direct DNS Egress Bypass
  [PASS] UDP/53: ['8.8.8.8', '1.1.1.1', '9.9.9.9']
  [PASS] TCP/53: ['8.8.8.8', '1.1.1.1', '9.9.9.9']
  [PASS] DoH: ['cloudflare', 'google']
  [PASS] DoT: ['8.8.8.8']

══════════════════════════════════════════════════════════════
ASSESSMENT SUMMARY
══════════════════════════════════════════════════════════════
  Target Resolver : 10.0.0.53
  OOB Domain      : somestring.oastify.com
  Duration        : 13.0s
  Overall Risk    : CRITICAL
  Note            : verify T3/T4/T6 via OOB; T7 reflects this host only.

  Test                                       Severity  Finding
  ───────────────────────────────────────────────────────────────────────────────
  T1 — External Relay Viability              HIGH      Resolver relays external DNS queries
  T2 — Record Type Coverage                  HIGH      TXT relay open — high-bandwidth covert channel viable (dnscat2, DNSExfiltrator)
  T3 — Query Payload: Label Length           HIGH      Resolver returns NXDOMAIN/NOERROR for labels up to 63 chars
  T4 — Query Payload: Entropy / IDS          HIGH      No SERVFAIL/drops for tested patterns
  T5 — Response Payload Capacity             MEDIUM    Moderate TXT payload relayed (66 chars) — chunked exfil viable
  T6 — Rate Limiting & Sustained Throughput  HIGH      No rate limiting detected — 30/30 resolved at 11.6 QPS (UDP burst)
  T7 — Direct DNS Egress Bypass              CRITICAL  Direct DNS egress available — filtering absent or incomplete

  [INFO] Report saved → bounce53_report.txt (raw queries: 108)
  [INFO] Global OOB search terms: see per-T OOB Check sections above (T3/T4: full long labels; T6: *.t6-ratelimit.* and *.t6-sustained.*)
```

***

## License

This project is licensed under the MIT License.

Copyright (c) VoidJarr

Released for authorized offensive security research and penetration testing. No warranty is provided. The author assumes no liability for misuse.
