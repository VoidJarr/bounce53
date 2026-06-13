#!/usr/bin/env python3
"""
bounce53.py — DNS Relay Exfiltration Assessment Tool
For authorized penetration testing use only.

Tests a corporate DNS resolver for susceptibility to DNS-based data
exfiltration / relay abuse using a linear seven-test model (T1–T7):

T1: External relay viability (UDP + TCP)
T2: Record type coverage (UDP full; TCP limited to A+TXT)
T3: Label length tolerance + qname minimization advisory
T4: High-entropy / IDS pattern tolerance
T5: Response payload capacity (TXT + EDNS probes + truncation + TCP fallback)
T6: Rate limiting (30-query burst + optional ~90-query sustained @ ~1 QPS)
T7: Direct egress bypass (UDP/53, TCP/53, DoH, best-effort DoT)

Results include per-transport details, raw dig capture (unless --no-raw),
OOB verification labels for heuristic tests, and actionable remediation.
"""

import argparse
import base64
import concurrent.futures
import datetime
import json
import math
import os
import shutil
import subprocess
import sys
import time


# ─── Colour helpers ────────────────────────────────────────────────────────────

def _c(code: str, no_color: bool = False) -> str:
    return "" if no_color else code

def RED(no_color: bool = False) -> str:    return _c("\033[91m", no_color)
def GREEN(no_color: bool = False) -> str:  return _c("\033[92m", no_color)
def YELLOW(no_color: bool = False) -> str: return _c("\033[93m", no_color)
def CYAN(no_color: bool = False) -> str:   return _c("\033[96m", no_color)
def BOLD(no_color: bool = False) -> str:   return _c("\033[1m", no_color)
def RESET(no_color: bool = False) -> str:  return _c("\033[0m", no_color)


# ─── DNS query helpers ──────────────────────────────────────────────────────────

def _execute_dig(resolver, name, qtype="A", timeout=5, use_short=False, tcp=False, bufsize: int | None = None):
    """
    Internal runner. Returns a rich dict with full dig output for raw capture.
    Always captures command, full stdout/stderr, returncode, and any exception.
    Supports +tcp when TCP transport is requested.
    bufsize sets EDNS UDP buffer size via +bufsize=N (for T5 EDNS probes).
    """
    tcp_flag = ["+tcp"] if tcp else []
    buf_flag = [f"+bufsize={bufsize}"] if bufsize is not None else []
    if use_short:
        cmd = [
            "dig", f"@{resolver}", name, qtype,
            "+short", f"+timeout={timeout}", "+tries=1"
        ] + tcp_flag + buf_flag
    else:
        cmd = [
            "dig", f"@{resolver}", name, qtype,
            f"+timeout={timeout}", "+tries=1"
        ] + tcp_flag + buf_flag

    rich = {
        "command": " ".join(cmd),
        "cmd_list": cmd,
        "resolver": resolver,
        "name": name,
        "qtype": qtype,
        "timeout": timeout,
        "bufsize": bufsize,
        "stdout": "",
        "stderr": "",
        "returncode": 1,
        "exception": None,
        "timestamp": datetime.datetime.now().isoformat(),
    }

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        rich["stdout"] = r.stdout
        rich["stderr"] = r.stderr
        rich["returncode"] = r.returncode
    except subprocess.TimeoutExpired as e:
        rich["exception"] = f"TimeoutExpired: {e}"
        # Best-effort partial output if available
        if hasattr(e, "stdout") and e.stdout:
            rich["stdout"] = e.stdout
        if hasattr(e, "stderr") and e.stderr:
            rich["stderr"] = e.stderr
    except FileNotFoundError as e:
        rich["exception"] = f"FileNotFoundError: {e} (is 'dig' installed?)"
    except Exception as e:
        rich["exception"] = f"{type(e).__name__}: {e}"

    return rich


def dig(resolver, name, qtype="A", timeout=5, tcp=False, bufsize: int | None = None):
    """Run a dig query with +short. Returns (stdout.strip(), returncode) for compatibility."""
    rich = _execute_dig(resolver, name, qtype, timeout, use_short=True, tcp=tcp, bufsize=bufsize)
    return rich["stdout"].strip(), rich["returncode"]


def dig_verbose(resolver, name, qtype="A", timeout=5, tcp=False, bufsize: int | None = None):
    """Return full dig output for RCODE inspection. Returns (stdout.strip(), returncode) for compatibility."""
    rich = _execute_dig(resolver, name, qtype, timeout, use_short=False, tcp=tcp, bufsize=bufsize)
    return rich["stdout"].strip(), rich["returncode"]


def dig_capture(resolver, name, qtype="A", timeout=5, short=False, tcp=False, bufsize: int | None = None):
    """
    Run dig and return the full rich result dict (command, stdout, stderr, returncode, exception, etc).
    Use this when you need raw query details for reporting or debugging.
    Pass tcp=True to query over TCP (+tcp).
    Pass bufsize=N to set EDNS UDP buffer size (+bufsize=N) for truncation/EDNS probes.
    """
    return _execute_dig(resolver, name, qtype, timeout, use_short=short, tcp=tcp, bufsize=bufsize)


def rcode_of(out_full):
    """
    Extract RCODE string from verbose dig output.
    Defensive parsing. Assumes common English dig output (BIND, musl, etc.).
    Extend pattern matching when unrecognized dig output formats are encountered.
    Locale differences or non-standard dig builds may still cause "UNKNOWN".
    """
    if not out_full:
        return "UNKNOWN"
    for line in out_full.splitlines():
        if "status:" in line:
            parts = line.split("status:")
            if len(parts) > 1:
                # Take text up to first comma or end of line, strip common punctuation
                status_part = parts[1].split(",")[0].strip().upper()
                status_part = status_part.rstrip(".,; ")
                if status_part:
                    return status_part
    # Fallback: look for common patterns in error output (expand as needed)
    lower = out_full.lower()
    if "connection timed out" in lower or "timeout" in lower or "timed out" in lower:
        return "TIMEOUT"
    if "server can't find" in lower or "nxdomain" in lower or "not found" in lower:
        return "NXDOMAIN"
    if "servfail" in lower or "server failure" in lower:
        return "SERVFAIL"
    if "refused" in lower or "query refused" in lower:
        return "REFUSED"
    if "connection refused" in lower or "network unreachable" in lower:
        return "UNREACHABLE"
    if "format error" in lower:
        return "FORMERR"
    return "UNKNOWN"


def parse_dig_header_flags(out_full):
    """
    Parse verbose dig output for header fields used by EDNS / response capacity probes.
    Returns a dict: {"rcode": str, "tc": bool, "answer_count": int, "flags_line": str or None}
    Defensive; falls back gracefully on unexpected dig output.
    """
    result = {"rcode": "UNKNOWN", "tc": False, "answer_count": 0, "flags_line": None}
    if not out_full:
        return result
    rcode = rcode_of(out_full)
    result["rcode"] = rcode
    for line in out_full.splitlines():
        lower = line.lower()
        if "flags:" in lower:
            result["flags_line"] = line.strip()
            # tc is in the flags section, e.g. ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1"
            if " tc" in lower or lower.endswith(" tc") or " tc;" in lower or " tc," in lower:
                result["tc"] = True
        # Capture ANSWER count from the ;; ->>HEADER or the QUERY: / ANSWER: summary line
        if "answer:" in lower:
            # Look for patterns like "ANSWER: 3," or "ANSWER: 0"
            try:
                # split on ANSWER: and take the number before comma or end
                parts = lower.split("answer:")
                if len(parts) > 1:
                    num_part = parts[1].strip().split(",")[0].strip()
                    result["answer_count"] = int(num_part)
            except Exception:
                pass
    # Fallback: if we saw "tc" anywhere in a flags-like context (rare)
    if not result["tc"] and ";;" in out_full and " tc" in out_full.lower():
        result["tc"] = True
    return result


# ─── Encoding helpers ───────────────────────────────────────────────────────────

def b32_encode(data: bytes) -> str:
    return base64.b32encode(data).decode().lower().rstrip("=")

def make_label_exact(target_chars: int) -> str:
    """
    Generate a base32-encoded label of exactly target_chars characters.
    base32: 5 raw bits per output char → ceil(target * 5 / 8) bytes needed.
    """
    n_bytes = math.ceil(target_chars * 5 / 8)
    raw = b"\x41" * n_bytes
    encoded = b32_encode(raw)
    return encoded[:target_chars]


# ══════════════════════════════════════════════════════════════════════════════
# 2. Core Test Logic (pure data collection)
#    - Each test returns a dict (no printing inside these functions).
#    - Private _tX_probe helpers stay here.
# ══════════════════════════════════════════════════════════════════════════════

def _t1_probe(resolver: str, oob_domain: str, timeout: int, tcp: bool = False) -> tuple[dict, list]:
    """Inner probe used for both UDP and TCP in T1 transport pair."""
    raw_collector = []  # caller merges
    fqdn = f"t1-relay.{oob_domain}"
    rich_oob   = dig_capture(resolver, fqdn, "A", timeout, short=True, tcp=tcp)
    rich_known = dig_capture(resolver, "google.com", "A", timeout, short=True, tcp=tcp)
    raw_collector.extend([rich_oob, rich_known])

    out_oob   = rich_oob["stdout"].strip()
    out_known = rich_known["stdout"].strip()

    relays_known = bool(out_known)
    relays_oob   = bool(out_oob)
    relays = relays_known or relays_oob

    sub = {
        "vulnerable": relays,
        "detail": f"google.com={relays_known}, {oob_domain}={relays_oob}",
    }
    return sub, raw_collector


def test_external_relay(resolver, oob_domain, timeout, udp_only=False, raw_collector: list | None = None) -> dict:
    """T1: External relay viability (UDP + TCP by default). Pure: returns result dict, no printing."""
    if raw_collector is None:
        raw_collector = []

    # UDP leg
    udp_sub, udp_raw = _t1_probe(resolver, oob_domain, timeout, tcp=False)
    raw_collector.extend(udp_raw)
    udp_vuln = udp_sub.get("vulnerable", False)

    # TCP leg (unless udp_only)
    if not udp_only:
        tcp_sub, tcp_raw = _t1_probe(resolver, oob_domain, timeout, tcp=True)
        raw_collector.extend(tcp_raw)
        tcp_vuln = tcp_sub.get("vulnerable", False)
    else:
        tcp_sub = {"skipped": True, "reason": "udp-only"}

    transport = {"udp": udp_sub, "tcp": tcp_sub}
    relays = (not udp_sub.get("skipped") and udp_sub.get("vulnerable")) or \
             (not tcp_sub.get("skipped") and tcp_sub.get("vulnerable"))

    t1_result = {
        "severity": "HIGH" if relays else "NONE",
        "finding": "Resolver relays external DNS queries" if relays else "Resolver does not relay external queries",
        "transport": transport,
    }

    # Note: caller (main) will do results[...] = returned_value and render_test(...)
    return t1_result


def _t2_probe(resolver: str, oob_domain: str, timeout: int, tcp: bool = False) -> tuple[dict, list]:
    """Inner probe for T2 over one transport."""
    types_to_test = ["A", "TXT", "MX", "CNAME", "NS", "AAAA"]
    fallback_map = {
        "A":    "google.com",
        "TXT":  "google.com",
        "MX":   "gmail.com",
        "AAAA": "google.com",
    }
    vulnerable_types = []
    raw = []

    for qtype in types_to_test:
        fqdn = f"t2-{qtype.lower()}.{oob_domain}"
        rich = dig_capture(resolver, fqdn, qtype, timeout, short=True, tcp=tcp)
        raw.append(rich)
        out = rich["stdout"].strip()
        source = oob_domain

        if not out and qtype in fallback_map:
            fb_domain = fallback_map[qtype]
            rich_fb = dig_capture(resolver, fb_domain, qtype, timeout, short=True, tcp=tcp)
            raw.append(rich_fb)
            out = rich_fb["stdout"].strip()
            source = fb_domain

        passed = bool(out)
        if passed:
            vulnerable_types.append(qtype)

    sub = {
        "relayed_types": vulnerable_types,
    }
    return sub, raw


def test_record_types(resolver, oob_domain, timeout, udp_only=False, raw_collector: list | None = None) -> dict:
    """T2: Record type coverage (UDP + TCP A/TXT by default). Pure: returns result dict, no printing."""
    if raw_collector is None:
        raw_collector = []

    # UDP
    udp_sub, udp_raw = _t2_probe(resolver, oob_domain, timeout, tcp=False)
    raw_collector.extend(udp_raw)
    udp_types = udp_sub.get("relayed_types", [])

    if not udp_only:
        tcp_sub, tcp_raw = _t2_probe(resolver, oob_domain, timeout, tcp=True)
        raw_collector.extend(tcp_raw)
        # TCP limited to A+TXT for this test
        tcp_types = [t for t in tcp_sub.get("relayed_types", []) if t in ("A", "TXT")]
        tcp_sub["relayed_types"] = tcp_types
    else:
        tcp_sub = {"skipped": True, "reason": "udp-only"}

    transport = {"udp": udp_sub, "tcp": tcp_sub}

    # Severity logic based on UDP primarily (TCP augments); keep similar rules
    vulnerable_types = udp_sub.get("relayed_types", [])
    if "TXT" in vulnerable_types:
        sev    = "HIGH"
        detail = "TXT relay open — high-bandwidth covert channel viable (dnscat2, DNSExfiltrator)"
    elif vulnerable_types:
        sev    = "MEDIUM"
        detail = f"{vulnerable_types} relayed — lower-bandwidth exfil still viable"
    else:
        sev    = "NONE"
        detail = "No external record types relayed"

    t2_result = {
        "severity": sev,
        "finding": detail,
        "transport": transport,
        "note": "TCP sub-result is limited to A and TXT record types (full set only on UDP).",
    }

    # caller assigns + renders
    return t2_result


def _t3_probe(resolver: str, oob_domain: str, timeout: int, tcp: bool = False) -> tuple[dict, list]:
    """Inner probe for T3 label lengths over one transport."""
    test_cases = [
        (30, "30-char label  (baseline)"),
        (45, "45-char label  (medium exfil chunk)"),
        (60, "60-char label  (typical dnscat2/DNSExfil)"),
        (63, "63-char label  (DNS spec maximum)"),
    ]
    label_results = {}
    raw = []

    for target_chars, desc in test_cases:
        label = make_label_exact(target_chars)
        if len(label) != target_chars:
            label_results[target_chars] = False
            continue
        fqdn = f"{label}.{oob_domain}"
        rich = dig_capture(resolver, fqdn, "A", timeout, short=False, tcp=tcp)
        raw.append(rich)
        out_full = rich["stdout"].strip()
        rcode = rcode_of(out_full)
        resolver_indicates_reach = rcode in ("NXDOMAIN", "NOERROR")
        label_results[target_chars] = resolver_indicates_reach

    passing = [c for c, ok in label_results.items() if ok]
    max_passing = max(passing) if passing else 0
    sub = {
        "per_label_results": label_results,
        "max_passing_chars": max_passing,
    }
    return sub, raw


def test_label_length(resolver, oob_domain, timeout, udp_only=False, raw_collector: list | None = None) -> dict:
    """T3: Query payload label length (UDP + TCP). Pure: returns result dict, no printing."""
    if raw_collector is None:
        raw_collector = []

    # UDP
    udp_sub, udp_raw = _t3_probe(resolver, oob_domain, timeout, tcp=False)
    raw_collector.extend(udp_raw)
    udp_max = udp_sub.get("max_passing_chars", 0)
    udp_per_label = udp_sub.get("per_label_results", {})

    # TCP
    if not udp_only:
        tcp_sub, tcp_raw = _t3_probe(resolver, oob_domain, timeout, tcp=True)
        raw_collector.extend(tcp_raw)
        tcp_max = tcp_sub.get("max_passing_chars", 0)
    else:
        tcp_sub = {"skipped": True, "reason": "udp-only"}

    transport = {"udp": udp_sub, "tcp": tcp_sub}

    # Severity from UDP max (TCP augments)
    max_passing = udp_max
    if max_passing >= 60:
        sev    = "HIGH"
        detail = f"Resolver returns NXDOMAIN/NOERROR for labels up to {max_passing} chars"
    elif max_passing >= 45:
        sev    = "MEDIUM"
        detail = f"Resolver returns NXDOMAIN/NOERROR for labels up to {max_passing} chars"
    elif max_passing > 0:
        sev    = "LOW"
        detail = f"Only short labels ({max_passing} chars) elicit NXDOMAIN/NOERROR"
    else:
        sev    = "NONE"
        detail = "No labels elicited NXDOMAIN/NOERROR"

    t3_result = {
        "severity": sev,
        "finding": detail,
        "transport": transport,
        "qname_minimization_risk": "unknown",
        "caveat": "HEURISTIC ONLY: NXDOMAIN/NOERROR may be synthesized by policy. Use OOB logs to confirm.",
    }

    oob60 = f"{make_label_exact(60)}.{oob_domain}"
    oob63 = f"{make_label_exact(63)}.{oob_domain}"
    t3_result["oob_check"] = [f"60-char: {oob60}", f"63-char: {oob63}"]

    # caller assigns + renders
    return t3_result


def _t4_probe(resolver: str, oob_domain: str, timeout: int, tcp: bool = False) -> tuple[dict, list, bool, list, list]:
    """Inner probe for T4 entropy cases over one transport. Returns (sub_dict, raw_list, bl_reached, entropy_reached_list)."""
    baseline = ("t4-low-entropy", "low-entropy     (human-readable — sanity check)")

    entropy_cases = [
        (f"{b32_encode(b'AAAA' * 9)[:40]}-t4b32rep",
         "base32 encoded  (repeating pattern, 40 chars)"),
        (f"{b32_encode(os.urandom(25))[:40]}-t4b32rnd",
         "base32 encoded  (random bytes, max entropy, 40 chars)"),
        ("4f3a9c2b7e1d6f8a0b5c9d3e7f2a4b6c-t4hex",
         "hex encoded     (32-char hex string)"),
    ]

    raw = []
    bl_label, bl_desc = baseline
    bl_fqdn   = f"{bl_label}.{oob_domain}"
    bl_rich   = dig_capture(resolver, bl_fqdn, "A", timeout, short=False, tcp=tcp)
    raw.append(bl_rich)
    bl_out    = bl_rich["stdout"].strip()
    bl_rcode  = rcode_of(bl_out)
    bl_reached = bl_rcode in ("NXDOMAIN", "NOERROR")

    entropy_blocked = 0
    entropy_total   = len(entropy_cases)
    entropy_reached = []  # for per-case console printing

    for label, desc in entropy_cases:
        fqdn     = f"{label}.{oob_domain}"
        rich     = dig_capture(resolver, fqdn, "A", timeout, short=False, tcp=tcp)
        raw.append(rich)
        out_full = rich["stdout"].strip()
        rcode    = rcode_of(out_full)
        resolver_indicates_reach  = rcode in ("NXDOMAIN", "NOERROR")
        blocked  = rcode == "SERVFAIL" or not out_full
        entropy_reached.append(resolver_indicates_reach)
        if blocked:
            entropy_blocked += 1

    sub = {
        "baseline_reached_auth": bl_reached,
        "patterns_blocked": entropy_blocked,
        "total_tested": entropy_total,
    }
    return sub, raw, bl_reached, entropy_reached, entropy_cases


def test_entropy(resolver, oob_domain, timeout, udp_only=False, raw_collector: list | None = None) -> dict:
    """T4: Query payload entropy/IDS (UDP + TCP). Pure: returns result dict, no printing."""
    if raw_collector is None:
        raw_collector = []

    # UDP
    udp_sub, udp_raw, bl_reached_udp, udp_entropy_reached, entropy_cases = _t4_probe(resolver, oob_domain, timeout, tcp=False)
    raw_collector.extend(udp_raw)
    udp_blocked = udp_sub.get("patterns_blocked", 0)
    udp_total = udp_sub.get("total_tested", 3)

    # TCP
    if not udp_only:
        tcp_sub, tcp_raw, bl_reached_tcp, tcp_entropy_reached, _ = _t4_probe(resolver, oob_domain, timeout, tcp=True)
        raw_collector.extend(tcp_raw)
        tcp_blocked = tcp_sub.get("patterns_blocked", 0)
    else:
        tcp_sub = {"skipped": True, "reason": "udp-only"}
        tcp_blocked = 0
        tcp_entropy_reached = [False] * 3
        bl_reached_tcp = False

    transport = {"udp": udp_sub, "tcp": tcp_sub}

    # Severity primarily from UDP (as before); TCP augments the transport result
    entropy_blocked = udp_blocked
    entropy_total = udp_total
    bl_reached = udp_sub.get("baseline_reached_auth", False)

    if entropy_blocked == 0:
        sev    = "HIGH"
        detail = "No SERVFAIL/drops for tested patterns"
    elif entropy_blocked < entropy_total:
        sev    = "MEDIUM"
        detail = f"{entropy_blocked}/{entropy_total} patterns blocked"
    else:
        sev    = "LOW"
        detail = f"All {entropy_total} patterns blocked"

    if not bl_reached:
        if sev == "HIGH":
            sev = "MEDIUM"
            detail = "(Baseline failed) " + detail

    t4_result = {
        "severity": sev,
        "finding": detail,
        "transport": transport,
        "caveat": "HEURISTIC: only these patterns tested. OOB verification required.",
        "oob_check": [
            f"{entropy_cases[0][0]}.{oob_domain}",
            f"{entropy_cases[1][0]}.{oob_domain}",
            f"{entropy_cases[2][0]}.{oob_domain}"
        ],
        # Per-pattern reachability (small, useful detail for reports + required for terminal render)
        "udp_reached": udp_entropy_reached,
        "tcp_reached": tcp_entropy_reached,
    }
    # caller assigns + renders
    return t4_result


def test_direct_egress(resolver, timeout, udp_only=False, skip_doh_dot=False, raw_collector: list | None = None) -> dict:
    """T7: Direct DNS egress bypass — UDP/53, TCP/53, DoH, (DoT best-effort). Pure: returns result dict."""
    if raw_collector is None:
        raw_collector = []
    external_resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    reachable = {"udp_53": [], "tcp_53": [], "doh": [], "dot": []}

    # UDP/53 direct
    for ext in external_resolvers:
        rich = dig_capture(ext, "google.com", "A", timeout, short=True, tcp=False)
        raw_collector.append(rich)
        out = rich["stdout"].strip()
        rc = rich["returncode"]
        if out and rc == 0:
            reachable["udp_53"].append(ext)

    # TCP/53 always probed (T7 direct bypass; not affected by --udp-only)
    for ext in external_resolvers:
        rich = dig_capture(ext, "google.com", "A", timeout, short=True, tcp=True)
        raw_collector.append(rich)
        out = rich["stdout"].strip()
        rc = rich["returncode"]
        if out and rc == 0:
            reachable["tcp_53"].append(ext)

    # DoH (curl to Cloudflare/Google; no Python deps)
    if not skip_doh_dot:
        doh_targets = [
            ("cloudflare", "https://cloudflare-dns.com/dns-query?name=google.com&type=A"),
            ("google", "https://dns.google/resolve?name=google.com&type=A"),
        ]
        for name, url in doh_targets:
            try:
                cmd = ["curl", "-s", "-H", "accept: application/dns-json", url]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
                raw_collector.append({
                    "command": " ".join(cmd),
                    "cmd_list": cmd,
                    "resolver": "doh:" + name,
                    "name": "google.com",
                    "qtype": "A",
                    "timeout": timeout,
                    "stdout": r.stdout[:2000],  # truncate for report sanity
                    "stderr": r.stderr,
                    "returncode": r.returncode,
                    "timestamp": datetime.datetime.now().isoformat(),
                })
                out = r.stdout.strip()
                # Light validation: A record or Status:0
                if r.returncode == 0 and out and ('"Status":0' in out or '"data":"' in out or "Answer" in out):
                    reachable["doh"].append(name)
            except Exception as e:
                # Error captured in raw_queries; do not add to reachable (treated as not reached)
                pass
    else:
        reachable["doh"] = ["skipped"]

    # DoT probe
    # DoT: prefer `dig +tls`; fallback to openssl s_client with tolerant success check
    # (many public DoT servers produce noisy shutdown even on usable connections).
    if not skip_doh_dot:
        for ext in external_resolvers[:1]:  # one is enough for feasibility
            dot_success = False
            dot_method = None

            # 1. Preferred accurate method: actual DoT resolution via dig +tls
            try:
                dig_cmd = ["dig", f"@{ext}", "+tls", "+short", "+timeout=5", "google.com", "A"]
                r = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=7)
                raw_collector.append({
                    "command": " ".join(dig_cmd),
                    "resolver": "dot:" + ext,
                    "stdout": (r.stdout or "")[:800],
                    "stderr": (r.stderr or "")[:800],
                    "returncode": r.returncode,
                    "timestamp": datetime.datetime.now().isoformat(),
                })
                out = (r.stdout or "").strip().lower()
                if r.returncode == 0 and out and "connection timed out" not in out and "servfail" not in out:
                    dot_success = True
                    dot_method = "dig +tls"
            except Exception:
                pass  # fall back to openssl

            if not dot_success:
                # 2. openssl s_client fallback
                try:
                    openssl_bin = shutil.which("openssl") or "openssl"
                    shell_cmd = f'echo | {openssl_bin} s_client -connect {ext}:853 -servername dns.google -ign_eof -brief -verify_quiet'
                    proc = subprocess.Popen(
                        ["sh", "-c", shell_cmd],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    try:
                        stdout, stderr = proc.communicate(timeout=6)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        stdout, stderr = proc.communicate()
                    combined = (stdout or "") + (stderr or "")
                    raw_collector.append({
                        "command": shell_cmd,
                        "resolver": "dot:" + ext,
                        "stdout": combined[:1200],
                        "stderr": "",
                        "returncode": proc.returncode if proc.returncode is not None else -1,
                        "timestamp": datetime.datetime.now().isoformat(),
                    })
                    cl = combined.lower()

                    hard_fails = ["connection refused", "name or service not known", "no route to host",
                                  "connection timed out", "handshake failure", "ssl alert number"]

                    positive = [
                        "connection established",
                        "verification: ok",
                        "peer certificate",
                        "verify return code: 0",
                    ]

                    has_hard = any(f in cl for f in hard_fails)
                    has_good = any(p in cl for p in positive)

                    if not has_hard and has_good:
                        dot_success = True
                        dot_method = "openssl s_client"

                except FileNotFoundError:
                    if not reachable["dot"]:
                        reachable["dot"] = ["skipped"]
                    break
                except Exception:
                    pass

            if dot_success:
                reachable["dot"].append(ext)

    else:
        reachable["dot"] = ["skipped"]

    # Severity: any successful path is CRITICAL (direct bypass of corp resolver)
    any_reachable = any(isinstance(v, list) and len(v) > 0 and v[0] != "skipped" for v in reachable.values())
    if any_reachable:
        sev = "CRITICAL"
        detail = "Direct DNS egress available — filtering absent or incomplete"
    else:
        sev = "NONE"
        detail = "Direct external DNS (UDP/TCP/DoH/DoT) blocked — hosts forced through corp resolver (or probes limited by host tooling)"

    t7_result = {
        "severity": sev,
        "finding": detail,
        "reachable": reachable,
        "caveat": "T7 measures only this host's egress (see global T7 Note in LIMITATIONS & CAVEATS for full details on internal hosts and tooling)."
    }
    # caller assigns
    return t7_result


def _single_rate_query(args: tuple) -> bool:
    """Worker for T6 concurrent rate limit test.
    Returns success_bool. Side-effects raw_collector if provided.
    """
    resolver, oob_domain, timeout, raw_collector, use_tcp = args
    label    = b32_encode(os.urandom(8))
    fqdn     = f"{label}.t6-ratelimit.{oob_domain}"
    rich     = dig_capture(resolver, fqdn, "A", timeout, short=False, tcp=use_tcp)
    if raw_collector is not None:
        raw_collector.append(rich)
    rcode    = rcode_of(rich["stdout"].strip())
    return rcode in ("NXDOMAIN", "NOERROR")


def _run_rate_burst(resolver: str, oob_domain: str, timeout: int, raw_collector: list, use_tcp: bool = False, query_count: int = 30, workers: int = 10) -> tuple[int, float, float]:
    """Run one burst phase, return (success, qps, elapsed)."""
    start = time.time()
    task_args = [(resolver, oob_domain, timeout, raw_collector, use_tcp)] * query_count
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        outcomes = list(ex.map(_single_rate_query, task_args))
    elapsed = time.time() - start
    success = sum(outcomes)
    qps     = success / elapsed if elapsed > 0 else 0
    return success, round(qps, 2), elapsed


def test_rate_limiting(resolver, oob_domain, timeout, udp_only=False, stealth_rate=False, raw_collector: list | None = None) -> dict:
    """T6: Rate limiting & sustained throughput (burst default; --stealth-rate for sustained phase). Pure: returns result dict."""
    if raw_collector is None:
        raw_collector = []
    query_count = 30
    workers     = 10

    # UDP burst
    udp_success, udp_qps, udp_elapsed = _run_rate_burst(resolver, oob_domain, timeout, raw_collector, use_tcp=False, query_count=query_count, workers=workers)

    udp_sub = {
        "queries_sent": query_count,
        "queries_resolved": udp_success,
        "qps": udp_qps,
        "elapsed": udp_elapsed,
    }

    # TCP burst
    if not udp_only:
        tcp_success, tcp_qps, tcp_elapsed = _run_rate_burst(resolver, oob_domain, timeout, raw_collector, use_tcp=True, query_count=query_count, workers=workers)
        tcp_sub = {
            "queries_sent": query_count,
            "queries_resolved": tcp_success,
            "qps": tcp_qps,
            "elapsed": tcp_elapsed,
        }
    else:
        tcp_sub = {"skipped": True, "reason": "udp-only"}

    transport = {"udp": udp_sub, "tcp": tcp_sub}

    # Severity from UDP burst (primary)
    success = udp_success
    qps = udp_qps
    if success >= query_count * 0.9:
        sev    = "HIGH"
        detail = f"No rate limiting detected — {success}/{query_count} resolved at {qps:.1f} QPS (UDP burst)"
    elif success >= query_count * 0.5:
        sev    = "MEDIUM"
        detail = f"Possible soft rate limiting — {success}/{query_count} resolved at {qps:.1f} QPS (UDP burst)"
    else:
        sev    = "LOW"
        detail = f"Rate limiting likely active — only {success}/{query_count} resolved (UDP burst)"

    burst_block = {
        "transport": transport,
        "queries_sent": query_count,
        "queries_resolved": udp_success,
        "qps": udp_qps,
    }

    t6 = {
        "severity": sev,
        "finding": detail,
        "burst": burst_block,
        "note": "Burst (default) + optional sustained (~1 QPS) via --stealth-rate. This host only.",
        "oob_check": [f"*.t6-ratelimit.{oob_domain}"]
    }

    if stealth_rate:
        s_query_count = 90
        sustained_start = time.time()
        sustained_sent = 0
        sustained_resolved = 0
        sustained_servfail = 0
        for i in range(s_query_count):
            label = b32_encode(os.urandom(8))
            fqdn = f"{label}.t6-sustained.{oob_domain}"
            rich = dig_capture(resolver, fqdn, "A", timeout, short=False, tcp=False)
            raw_collector.append(rich)
            sustained_sent += 1
            rcode = rcode_of(rich["stdout"].strip())
            if rcode in ("NXDOMAIN", "NOERROR"):
                sustained_resolved += 1
            elif rcode == "SERVFAIL":
                sustained_servfail += 1
            time.sleep(0.9)  # ~1 QPS target
        sustained_elapsed = time.time() - sustained_start
        servfail_rate = (sustained_servfail / sustained_sent) if sustained_sent > 0 else 0.0
        t6["sustained"] = {
            "enabled": True,
            "queries_sent": sustained_sent,
            "queries_resolved": sustained_resolved,
            "servfail_rate": round(servfail_rate, 3),
            "duration_s": round(sustained_elapsed, 1),
        }
        t6["oob_check"] = [f"*.t6-ratelimit.{oob_domain}", f"*.t6-sustained.{oob_domain}"]
        t6["finding"] = f"No rate limiting detected — burst {query_count}/{query_count} at {qps:.1f} QPS (UDP); sustained {sustained_resolved}/{sustained_sent} resolved (servfail_rate={servfail_rate:.2f})"
    else:
        t6["sustained"] = {"enabled": False}

    # caller assigns
    return t6


def _t5_probe(resolver: str, oob_domain: str, timeout: int, tcp: bool = False) -> tuple[dict, list]:
    """Inner probe for response capacity TXT size over one transport."""
    raw = []
    oob_txt_fqdn  = f"t5-payload.{oob_domain}"
    rich_oob    = dig_capture(resolver, oob_txt_fqdn, "TXT", timeout, short=True, tcp=tcp)
    rich_google = dig_capture(resolver, "google.com", "TXT", timeout, short=True, tcp=tcp)
    raw.extend([rich_oob, rich_google])

    out_oob    = rich_oob["stdout"].strip()
    out_google = rich_google["stdout"].strip()

    if out_oob:
        payload_len = len(out_oob)
        source      = oob_txt_fqdn
    else:
        payload_len = len(out_google) if out_google else 0
        source      = "google.com (fallback)" if out_google else "none"

    sub = {
        "payload_length_chars": payload_len,
        "source": source,
    }
    return sub, raw


def test_response_capacity(resolver, oob_domain, timeout, udp_only=False, raw_collector: list | None = None) -> dict:
    """T5: Response Payload Capacity (TXT + EDNS probes + truncation + TCP fallback). Pure: returns result dict, no printing."""
    if raw_collector is None:
        raw_collector = []

    udp_sub, udp_raw = _t5_probe(resolver, oob_domain, timeout, tcp=False)
    raw_collector.extend(udp_raw)
    udp_len = udp_sub.get("payload_length_chars", 0)
    udp_src = udp_sub.get("source", "unknown")

    if not udp_only:
        tcp_sub, tcp_raw = _t5_probe(resolver, oob_domain, timeout, tcp=True)
        raw_collector.extend(tcp_raw)
        tcp_len = tcp_sub.get("payload_length_chars", 0)
        tcp_src = tcp_sub.get("source", "unknown")
    else:
        tcp_sub = {"skipped": True, "reason": "udp-only"}

    transport = {"udp": udp_sub, "tcp": tcp_sub}

    payload_len = udp_len  # primary for severity in P2
    if not udp_len and not udp_sub.get("skipped"):
        # no TXT at all
        t5_result = {
            "severity": "NONE",
            "finding": "TXT record type not relayed — T2 should also show TXT blocked",
            "transport": transport,
        }
        return t5_result

    if payload_len >= 200:
        sev    = "HIGH"
        detail = f"Large TXT payloads relay intact ({payload_len} chars) — high-bandwidth exfil viable"
    elif payload_len >= 50:
        sev    = "MEDIUM"
        detail = f"Moderate TXT payload relayed ({payload_len} chars) — chunked exfil viable"
    else:
        sev    = "LOW"
        detail = f"Small TXT payload only ({payload_len} chars) — possible response truncation"

    t5_result = {
        "severity": sev,
        "finding": detail,
        "transport": transport,
        "txt_payload_chars": payload_len,
        "note": "TXT response size + EDNS probes (512/1232/4096), truncation, and TCP fallback. Values from this host only.",
    }

    # EDNS bufsize probes + truncation/TCP fallback test
    # Use payload name if available, else google fallback.
    payload_fqdn = f"t5-payload.{oob_domain}"
    edns_name = payload_fqdn if udp_len > 0 else "google.com"
    edns_probes = []
    truncation_observed = False
    for bs in (512, 1232, 4096):
        rich = dig_capture(resolver, edns_name, "TXT", timeout, short=False, tcp=False, bufsize=bs)
        raw_collector.append(rich)
        parsed = parse_dig_header_flags(rich["stdout"])
        probe = {
            "bufsize": bs,
            "rcode": parsed.get("rcode", "UNKNOWN"),
            "tc": bool(parsed.get("tc")),
            "answer_count": parsed.get("answer_count", 0),
        }
        edns_probes.append(probe)
        if probe["tc"]:
            truncation_observed = True

    tcp_fallback_works = None
    if truncation_observed:
        # Retry over TCP for the same name (large buf) to test fallback
        rich_fb = dig_capture(resolver, edns_name, "TXT", timeout, short=False, tcp=True, bufsize=4096)
        raw_collector.append(rich_fb)
        fb_rc = rcode_of(rich_fb["stdout"].strip())
        tcp_fallback_works = fb_rc in ("NOERROR", "NXDOMAIN")
        edns_probes.append({
            "bufsize": "tcp-fallback",
            "rcode": fb_rc,
            "tc": False,
            "answer_count": parse_dig_header_flags(rich_fb["stdout"]).get("answer_count", 0),
        })

    t5_result["edns_probes"] = edns_probes
    t5_result["truncation_observed"] = truncation_observed
    if tcp_fallback_works is not None:
        t5_result["tcp_fallback_works"] = tcp_fallback_works

    # caller (main) assigns the returned value
    return t5_result


# ══════════════════════════════════════════════════════════════════════════════
# (end of 2. Core Test Logic)
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# 3. Result Assembly & Transport Helpers
#    - run_transport_pair, merge_transport_severity, etc.
#    - Post-processing that combines results.
# ══════════════════════════════════════════════════════════════════════════════

def run_transport_pair(fn, *args, udp: bool = True, tcp: bool = True, **kwargs) -> dict:
    """
    Execute a probe callable over UDP and/or TCP and return a nested transport result.
    fn must accept a `tcp: bool` kwarg (and forward other args) and return a dict sub-result.
    Honours udp_only (when present in kwargs or as flag) by setting tcp sub-result to {"skipped": true, "reason": "..."}.
    Returns: {"udp": <dict>, "tcp": <dict>}
    """
    udp_only = kwargs.pop("udp_only", False)
    transport = {}
    if udp:
        transport["udp"] = fn(*args, tcp=False, **kwargs) or {}
    else:
        transport["udp"] = {"skipped": True, "reason": "udp disabled"}
    if tcp and not udp_only:
        transport["tcp"] = fn(*args, tcp=True, **kwargs) or {}
    else:
        transport["tcp"] = {"skipped": True, "reason": "udp-only" if udp_only else "tcp disabled"}
    return transport


def merge_transport_severity(udp_result: dict, tcp_result: dict, default: str = "NONE") -> str:
    """
    Given two sub-result dicts (or skipped), return the worst severity across UDP and TCP.
    Uses the module SEVERITY_ORDER. Skipped entries do not affect the outcome.
    """
    worst = default
    for sub in (udp_result, tcp_result):
        if not isinstance(sub, dict):
            continue
        if sub.get("skipped"):
            continue
        sev = sub.get("severity")
        if sev and SEVERITY_ORDER.get(sev, 99) < SEVERITY_ORDER.get(worst, 99):
            worst = sev
    return worst


# ══════════════════════════════════════════════════════════════════════════════
# (end of 3. Result Assembly)
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# 4. Output / Presentation Layer (all printing lives here)
#    - banner, pass/fail/info labels
#    - render_terminal
#    - write_report (JSON + human TXT)
#    - Helper formatters for complex fields (Transport, EDNS, OOB Check, burst, etc.)
# ══════════════════════════════════════════════════════════════════════════════

def pass_label(no_color: bool = False) -> str:  return f"{GREEN(no_color)}[PASS]{RESET(no_color)}"
def fail_label(no_color: bool = False) -> str:  return f"{RED(no_color)}[FAIL]{RESET(no_color)}"
def warn_label(no_color: bool = False) -> str:  return f"{YELLOW(no_color)}[WARN]{RESET(no_color)}"
def info_label(no_color: bool = False) -> str:  return f"{CYAN(no_color)}[INFO]{RESET(no_color)}"

def severity_str(level: str, no_color: bool = False) -> str:
    return {
        "CRITICAL": f"{RED(no_color)}{BOLD(no_color)}CRITICAL{RESET(no_color)}",
        "HIGH":     f"{RED(no_color)}HIGH{RESET(no_color)}",
        "MEDIUM":   f"{YELLOW(no_color)}MEDIUM{RESET(no_color)}",
        "LOW":      f"{CYAN(no_color)}LOW{RESET(no_color)}",
        "NONE":     f"{GREEN(no_color)}NONE{RESET(no_color)}",
    }.get(level, level)


def _render_t3(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T3 render."""
    transport = result.get("transport", {})
    udp_sub = transport.get("udp", {})
    tcp_sub = transport.get("tcp", {})
    udp_max = udp_sub.get("max_passing_chars", 0)
    udp_per_label = udp_sub.get("per_label_results", {})
    for tc in sorted(udp_per_label.keys()):
        ok = udp_per_label[tc]
        desc = MESSAGES["t3_label_descriptions"].get(tc, f"{tc}-char label")
        if ok:
            print(f"  {pass_label(no_color)} UDP {desc} → resolver returned NXDOMAIN/NOERROR (heuristic)")
        else:
            print(f"  {fail_label(no_color)} UDP {desc} → dropped/SERVFAIL (heuristic)")
    if udp_max > 0:
        print(f"  {info_label(no_color)} UDP max passing chars: {udp_max}")
    passing = [c for c, ok in udp_per_label.items() if ok]
    if passing and len(passing) > 1 and min(passing) != sorted(passing)[0]:
        print(f"  {warn_label(no_color)} {MESSAGES['non_monotonic_warn']}")
    if not tcp_sub.get("skipped"):
        tcp_max = tcp_sub.get("max_passing_chars", 0)
        if tcp_max > 0:
            print(f"  {pass_label(no_color)} TCP max passing chars: {tcp_max}")
        else:
            print(f"  {warn_label(no_color)} TCP no labels passed (or all dropped)")
        tcp_per = tcp_sub.get("per_label_results", {})
        tcp_passing = [c for c, ok in tcp_per.items() if ok]
        if tcp_passing and len(tcp_passing) > 1 and min(tcp_passing) != sorted(tcp_passing)[0]:
            print(f"  {warn_label(no_color)} TCP {MESSAGES['non_monotonic_warn']}")
    # OOB exact labels (aligned continuation as per production polish)
    items = _format_oob_check(result.get("oob_check", []))
    if items:
        print(f"  {info_label(no_color)} OOB check: {items[0]}")
        for extra in items[1:]:
            print(f"                    {extra}")


def _render_t1(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T1 render."""
    transport = result.get("transport", {})
    udp_sub = transport.get("udp", {})
    tcp_sub = transport.get("tcp", {})
    udp_vuln = (not udp_sub.get("skipped") and udp_sub.get("vulnerable"))
    udp_lbl = pass_label(no_color) if udp_vuln else fail_label(no_color)
    print(f"  {udp_lbl} UDP google.com + t1-relay.{oob_domain} → {'answer(s) received' if udp_vuln else 'no answer'}")
    if not tcp_sub.get("skipped"):
        tcp_vuln = tcp_sub.get("vulnerable", False)
        tcp_lbl = pass_label(no_color) if tcp_vuln else fail_label(no_color)
        print(f"  {tcp_lbl} TCP google.com + t1-relay.{oob_domain} → {'answer(s) received' if tcp_vuln else 'no answers over TCP'}")
    # no extra Note for T1 (consistent with prior polish)


def _render_t2(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T2 render."""
    transport = result.get("transport", {})
    udp_sub = transport.get("udp", {})
    tcp_sub = transport.get("tcp", {})
    udp_types = udp_sub.get("relayed_types", [])
    if udp_types:
        print(f"  {pass_label(no_color)} UDP relayed: {', '.join(udp_types)}")
    else:
        print(f"  {fail_label(no_color)} UDP relayed: none")
    if not tcp_sub.get("skipped"):
        tcp_types = tcp_sub.get("relayed_types", [])
        if tcp_types:
            print(f"  {pass_label(no_color)} TCP (A+TXT only) relayed: {', '.join(tcp_types)}")
        else:
            print(f"  {fail_label(no_color)} TCP (A+TXT only) relayed: none")


def _render_t4(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T4 render."""
    udp_reached = result.get("udp_reached", [])
    tcp_reached = result.get("tcp_reached", [])
    transport = result.get("transport", {})
    udp_sub = transport.get("udp", {})
    tcp_sub = transport.get("tcp", {})

    # Static descriptions from MESSAGES (stable)
    pattern_descs = MESSAGES["t4_pattern_descs"]
    oob_items = _format_oob_check(result.get("oob_check", []))
    # Extract the label prefix (before .oob) for display, matching original terminal style
    short_labels = [item.split(".")[0] if "." in item else item for item in oob_items]

    print(f"  {info_label(no_color)} UDP baseline reached: {udp_sub.get('baseline_reached_auth')}")
    for (short, desc), reached in zip(zip(short_labels, pattern_descs), udp_reached):
        lbl = pass_label(no_color) if reached else fail_label(no_color)
        print(f"  {lbl} UDP {desc} → {'reached auth NS' if reached else 'SERVFAIL/dropped — possible IDS block'}")
    print(f"  {info_label(no_color)} UDP patterns blocked: {udp_sub.get('patterns_blocked', 0)}/{udp_sub.get('total_tested', 3)}")

    if not tcp_sub.get("skipped"):
        print(f"  {info_label(no_color)} TCP baseline reached: {tcp_sub.get('baseline_reached_auth', False)}")
        for (short, desc), reached in zip(zip(short_labels, pattern_descs), tcp_reached):
            lbl = pass_label(no_color) if reached else fail_label(no_color)
            print(f"  {lbl} TCP {desc} → {'reached auth NS' if reached else 'SERVFAIL/dropped — possible IDS block'}")
        print(f"  {info_label(no_color)} TCP patterns blocked: {tcp_sub.get('patterns_blocked', 0)}/{tcp_sub.get('total_tested', 3)}")

    # OOB (the actionable verification labels)
    if oob_items:
        print(f"  {info_label(no_color)} OOB check: {oob_items[0]}")
        for extra in oob_items[1:]:
            print(f"                    {extra}")


def _render_t5(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T5 render."""
    transport = result.get("transport", {})
    udp = transport.get("udp", {})
    tcp = transport.get("tcp", {})
    print(f"  {pass_label(no_color) if udp.get('payload_length_chars', 0) > 0 else fail_label(no_color)} UDP TXT payload → {udp.get('payload_length_chars', 0)} chars via {udp.get('source', 'unknown')}")
    if not tcp.get("skipped"):
        print(f"  {pass_label(no_color) if tcp.get('payload_length_chars', 0) > 0 else warn_label(no_color)} TCP TXT payload → {tcp.get('payload_length_chars', 0)} chars via {tcp.get('source', 'unknown')}")


def _render_t6(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T6 render."""
    burst = result.get("burst", {})
    transport = burst.get("transport", {}) if isinstance(burst, dict) else {}
    udp_b = transport.get("udp", {}) if isinstance(transport, dict) else {}
    tcp_b = transport.get("tcp", {}) if isinstance(transport, dict) else {}

    u_sent = burst.get("queries_sent", 30)
    u_res = udp_b.get("queries_resolved", burst.get("queries_resolved", 0))
    u_qps = udp_b.get("qps", burst.get("qps", 0))
    u_el = udp_b.get("elapsed", 0)
    print(f"  {info_label(no_color)} UDP burst: {u_res}/{u_sent} @ {u_qps:.1f} QPS ({u_el:.1f}s)")

    if not tcp_b.get("skipped"):
        t_res = tcp_b.get("queries_resolved", u_res)
        t_qps = tcp_b.get("qps", 0)
        t_el = tcp_b.get("elapsed", 0)
        print(f"  {info_label(no_color)} TCP burst: {t_res}/{u_sent} @ {t_qps:.1f} QPS ({t_el:.1f}s)")

    finding = result.get("finding", "")
    if finding:
        print(f"  {warn_label(no_color)} {finding}")

    sustained = result.get("sustained", {})
    if isinstance(sustained, dict) and sustained.get("enabled"):
        s_res = sustained.get("queries_resolved", 0)
        s_sent = sustained.get("queries_sent", 0)
        s_rate = sustained.get("servfail_rate", 0.0)
        s_dur = sustained.get("duration_s", 0)
        print(f"  {info_label(no_color)} Burst: {u_res}/{u_sent} @ {u_qps:.1f} QPS (UDP) | Sustained: {s_res}/{s_sent} resolved, servfail={s_rate:.2f}, {s_dur:.1f}s")

    # OOB (use the shared formatter)
    items = _format_oob_check(result.get("oob_check", []))
    if items:
        if len(items) > 1:
            print(f"  {info_label(no_color)} OOB check: {items[0]} ; {items[1]}")
        else:
            print(f"  {info_label(no_color)} OOB check: {items[0]}")


def _render_t7(result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Small helper for T7 render."""
    reachable = result.get("reachable", {})
    r_lines = _format_reachable(reachable)
    # The familiar 4-line grouped output
    for line in r_lines:
        if line.startswith("udp_53:"):
            val = line.split(":", 1)[1].strip()
            if val and val != "[]":
                print(f"  {pass_label(no_color)} UDP/53: {val}")
            else:
                print(f"  {fail_label(no_color)} UDP/53: blocked")
        elif line.startswith("tcp_53:"):
            val = line.split(":", 1)[1].strip()
            if val and val != "[]":
                print(f"  {pass_label(no_color)} TCP/53: {val}")
            else:
                print(f"  {fail_label(no_color)} TCP/53: blocked")
        elif line.startswith("doh:"):
            val = line.split(":", 1)[1].strip()
            if val == "skipped":
                pass
            elif val and val != "[]":
                print(f"  {pass_label(no_color)} DoH: {val}")
            else:
                print(f"  {fail_label(no_color)} DoH: blocked or error")
        elif line.startswith("dot:"):
            val = line.split(":", 1)[1].strip()
            if val == "skipped":
                pass
            elif val and val != "[]":
                print(f"  {pass_label(no_color)} DoT: {val}")
            else:
                print(f"  {warn_label(no_color)} DoT: probe did not succeed")


def render_test(test_id: str, result: dict, oob_domain: str, no_color: bool = False) -> None:
    """Render the live terminal section for a single test result.
    This centralizes all per-test progress/status/note/OOB printing.
    Called immediately after each test returns its data (preserves live feedback timing).
    """
    if not isinstance(result, dict):
        return
    title = TEST_TITLES.get(test_id, test_id)
    print(f"\n{BOLD(no_color)}{title}{RESET(no_color)}")

    if test_id == "T1_external_relay":
        _render_t1(result, oob_domain, no_color)

    elif test_id == "T2_record_types":
        _render_t2(result, oob_domain, no_color)

    elif test_id == "T3_label_length":
        _render_t3(result, oob_domain, no_color)

    elif test_id == "T4_entropy":
        _render_t4(result, oob_domain, no_color)

    elif test_id == "T5_response_capacity":
        _render_t5(result, oob_domain, no_color)

    elif test_id == "T6_rate_limiting":
        _render_t6(result, oob_domain, no_color)

    elif test_id == "T7_direct_egress":
        _render_t7(result, oob_domain, no_color)


def render_terminal(results: dict, resolver: str, oob_domain: str, elapsed: float, args: argparse.Namespace, no_color: bool = False, json_path: str | None = None, txt_path: str | None = None, raw_count: int = 0) -> None:
    """Full post-run terminal rendering (summary + end messages).
    Per-test rendering is done live via direct render_test calls from main.
    """
    # Summary
    print_summary(results, resolver, oob_domain, elapsed, no_color)

    # End-of-run messages (owned here for zero side-effects in write_report)
    saved = []
    if json_path:
        saved.append(json_path)
    if txt_path:
        saved.append(txt_path)
    if saved:
        print(f"\n  {info_label(no_color)} Report saved → {', '.join(saved)} (raw queries: {raw_count if raw_count else 'disabled (--no-raw)'})")

    # Global OOB search terms (one-line collector at very bottom for quick copy-paste)
    oob_terms = []
    for k, v in results.items():
        if isinstance(v, dict) and "oob_check" in v:
            oc = v["oob_check"]
            if isinstance(oc, list):
                oob_terms.extend(oc)
            else:
                oob_terms.append(oc)
    if oob_terms:
        print(f"  {info_label(no_color)} Global OOB search terms: see per-T OOB Check sections above (T3/T4: full long labels; T6: *.t6-ratelimit.* and *.t6-sustained.*)")


def _format_oob_check(oob_check: list | str) -> list[str]:
    """Return list of lines for OOB Check (used by both render and TXT writer)."""
    if isinstance(oob_check, list):
        items = [str(x).strip() for x in oob_check if str(x).strip()]
    else:
        items = [line.strip() for line in str(oob_check).splitlines() if line.strip()]
    return items


def _format_transport(transport: dict) -> list[str]:
    """Compact multi-line representation for a transport dict (udp/tcp legs)."""
    lines = []
    for leg in ("udp", "tcp"):
        sub = transport.get(leg, {}) if isinstance(transport, dict) else {}
        if isinstance(sub, dict):
            if sub.get("skipped"):
                lines.append(f"{leg}: skipped ({sub.get('reason')})")
            else:
                parts = []
                for k, val in sub.items():
                    if k == "per_label_results" and isinstance(val, dict):
                        passing = sorted([c for c, ok in val.items() if ok])
                        val_str = f"passing={passing}" if passing else "passing=none"
                    elif isinstance(val, (dict, list)):
                        val_str = str(val)
                    else:
                        val_str = str(val)
                    parts.append(f"{k}={val_str}")
                if parts:
                    lines.append(f"{leg}: {', '.join(parts)}")
    return lines


def _format_burst(burst: dict) -> list[str]:
    """Format the burst block (used in terminal render and TXT)."""
    lines = []
    if not isinstance(burst, dict):
        return lines
    transport = burst.get("transport", {})
    tlines = _format_transport(transport)
    if tlines:
        lines.append("transport: " + " ; ".join(tlines) if len(tlines) > 1 else tlines[0])
    for k in ("queries_sent", "queries_resolved", "qps"):
        if k in burst:
            lines.append(f"{k}: {burst[k]}")
    return lines


def _format_sustained(sust: dict) -> list[str]:
    """Format sustained block."""
    if not isinstance(sust, dict):
        return []
    if sust.get("enabled") is False:
        return ["enabled: false"]
    out = []
    for k in ("enabled", "queries_sent", "queries_resolved", "servfail_rate", "duration_s"):
        if k in sust:
            out.append(f"{k}: {sust[k]}")
    return out


def _format_reachable(reach: dict) -> list[str]:
    """Format the T7 reachable summary."""
    lines = []
    if not isinstance(reach, dict):
        return lines
    for proto in ("udp_53", "tcp_53", "doh", "dot"):
        lst = reach.get(proto, [])
        if lst == ["skipped"]:
            lines.append(f"{proto}: skipped")
        elif lst:
            lines.append(f"{proto}: {lst}")
        else:
            lines.append(f"{proto}: []")
    return lines


def _format_edns_probes(probes: list) -> list[str]:
    """Format EDNS probe list for display."""
    lines = []
    if not isinstance(probes, list):
        return lines
    for p in probes:
        if isinstance(p, dict):
            bs = p.get("bufsize")
            rc = p.get("rcode", "?")
            tc = p.get("tc", False)
            ans = p.get("answer_count", 0)
            extra = f" ({p.get('note')})" if p.get("note") else ""
            lines.append(f"bufsize={bs}: {rc} (tc={tc}, ans={ans}){extra}")
    return lines


# Small dict for duplicated presentational static text (used by render and sometimes data shaping)
MESSAGES = {
    "t3_label_descriptions": {
        30: "30-char label  (baseline)",
        45: "45-char label  (medium exfil chunk)",
        60: "60-char label  (typical dnscat2/DNSExfil)",
        63: "63-char label  (DNS spec maximum)",
    },
    "t4_pattern_descs": [
        "base32 encoded  (repeating pattern, 40 chars)",
        "base32 encoded  (random bytes, max entropy, 40 chars)",
        "hex encoded     (32-char hex string)",
    ],
    "non_monotonic_warn": "Non-monotonic results — verify OOB NS is receiving queries.",
}


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}

# Display names and formatting for the human-readable .txt report.
# All labels start with capital letter, colons are uniformly padded for alignment.
LABEL_WIDTH = 24
DISPLAY_NAMES = {
    "vulnerable": "Vulnerable",
    "detail": "Detail",
    "relayed_types": "Relayed types",
    "per_label_results": "Per label results",
    "max_passing_chars": "Max passing chars",
    "baseline_reached_auth": "Baseline reached auth",
    "patterns_blocked": "Patterns blocked",
    "total_tested": "Total tested",
    "udp_reached": "UDP Reached",
    "tcp_reached": "TCP Reached",
    "reachable": "Reachable",
    "queries_sent": "Queries sent",
    "queries_resolved": "Queries resolved",
    "qps": "QPS",
    "payload_length_chars": "Payload length chars",
    "source": "Source",
    "note": "Note",
    "caveat": "Caveat",
    "transport": "Transport",
    "txt_payload_chars": "TXT Payload Chars",
    "edns_probes": "EDNS Probes",
    "truncation_observed": "Truncation Observed",
    "tcp_fallback_works": "TCP fallback works",
    "qname_minimization_risk": "Qname Minimization Risk",
    "tcp_vulnerable": "TCP vulnerable",
    "tcp_detail": "TCP detail",
}

TEST_TITLES = {
    "T1_external_relay": "T1 — External Relay Viability",
    "T2_record_types": "T2 — Record Type Coverage",
    "T3_label_length": "T3 — Query Payload: Label Length",
    "T4_entropy": "T4 — Query Payload: Entropy / IDS",
    "T5_response_capacity": "T5 — Response Payload Capacity",
    "T6_rate_limiting": "T6 — Rate Limiting & Sustained Throughput",
    "T7_direct_egress": "T7 — Direct DNS Egress Bypass",
}

REMEDIATION_LABELS = {
    "immediate": "Immediate",
    "short_term": "Short Term",
    "medium_term": "Medium Term",
    "strategic": "Strategic",
    "mitre_attack": "MITRE ATT&CK",
}

LIMITATIONS_LABELS = {
    "summary": "Summary",
    "t2_note": "T2 Note",
    "t3_note": "T3 Note",
    "t3_qname_note": "T3 Qname Note",
    "t4_note": "T4 Note",
    "t5_note": "T5 Note",
    "t6_note": "T6 Note",
    "t7_note": "T7 Note",
    "fallback_note": "Fallback Note",
    "raw_note": "Raw Note",
}

def _display_label(key: str) -> str:
    if key in DISPLAY_NAMES:
        return DISPLAY_NAMES[key]
    # Fallback: Title Case with spaces
    return key.replace("_", " ").title()


def overall_severity(results: dict) -> str:
    worst = "NONE"
    for v in results.values():
        if isinstance(v, dict) and "severity" in v:
            if SEVERITY_ORDER.get(v["severity"], 99) < SEVERITY_ORDER.get(worst, 99):
                worst = v["severity"]
    return worst

def print_summary(results: dict, resolver: str, oob_domain: str, elapsed: float, no_color: bool = False) -> None:
    overall = overall_severity(results)
    print(f"\n{'═'*62}")
    print(f"{BOLD(no_color)}ASSESSMENT SUMMARY{RESET(no_color)}")
    print(f"{'═'*62}")
    print(f"  Target Resolver : {resolver}")
    print(f"  OOB Domain      : {oob_domain}")
    print(f"  Duration        : {elapsed:.1f}s")
    print(f"  Overall Risk    : {severity_str(overall, no_color)}")
    print(f"  Note            : verify T3/T4/T6 via OOB; T7 reflects this host only.")
    print()

    rows = []
    for k, v in results.items():
        if isinstance(v, dict):
            title = TEST_TITLES.get(k, k)
            rows.append([title, v.get("severity", "?"), v.get("finding", "")])

    col_w = [
        max(len("Test"),     max((len(r[0]) for r in rows), default=0)),
        max(len("Severity"), max((len(r[1]) for r in rows), default=0)),
    ]

    print(f"  {'Test':<{col_w[0]}}  {'Severity':<{col_w[1]}}  Finding")
    print("  " + "─" * (col_w[0] + col_w[1] + 30))
    for r in rows:
        pad = col_w[1] - len(r[1])
        print(f"  {r[0]:<{col_w[0]}}  {severity_str(r[1], no_color)}{' ' * pad}  {r[2]}")


def write_report(results: dict, resolver: str, oob_domain: str, output_path: str, elapsed: float, args: argparse.Namespace, output_formats: list[str] | None = None) -> tuple[str | None, str | None]:
    """Write JSON and/or TXT reports. Pure I/O only — no side-effect printing.
    output_formats: list like ["txt"] or ["txt", "json"]
    Returns (json_path, txt_path) — either may be None if not requested.
    """
    if output_formats is None:
        output_formats = ["txt", "json"]
    output_formats = [f.lower() for f in output_formats]

    overall   = overall_severity(results)
    ts        = datetime.datetime.now().isoformat()
    base      = os.path.splitext(output_path)[0]
    json_path = base + ".json" if "json" in output_formats else None
    txt_path  = base + ".txt" if "txt" in output_formats else None

    raw_queries = results.get("_raw_queries", [])
    if getattr(args, "no_raw", False):
        raw_queries = []
    raw_queries = list(raw_queries)  # copy to avoid any later issues

    render_only_keys = {"udp_reached", "tcp_reached"}
    findings = {k: v for k, v in results.items() if k != "_raw_queries" and k not in render_only_keys}

    report = {
        "metadata": {
            "tool":             "bounce53.py",
            "schema_version":   "1",
            "timestamp":        ts,
            "target_resolver":  resolver,
            "oob_domain":       oob_domain,
            "duration_seconds": round(elapsed, 2),
            "overall_severity": overall,
            "raw_query_count":  len(raw_queries),
            "raw_captured":     not getattr(args, "no_raw", False),
        },
        "parameters": vars(args),
        "findings":   findings,
        "raw_queries": raw_queries,
    }

    report["limitations_and_caveats"] = {
        "summary": "Bounce53 primarily uses resolver RCODEs (T3/T4) and response success rates (T6) as heuristics. These are frequently synthesized by RPZ, security products, firewalls, or the resolver itself and do NOT prove the query reached the authoritative server. T7 measures only the assessment host's direct egress — internal hosts almost always face stricter controls. Cross raw_queries against real OOB/authoritative logs for ground truth.",
        "t2_note": "TCP results for T2 are limited to A and TXT record types by design. Full coverage (MX, CNAME, NS, AAAA) is tested only over UDP.",
        "t3_note": "Long labels returning NXDOMAIN/NOERROR are a heuristic only. Policy layers can return identical responses without upstream relay. OOB verification is required before claiming exfil bandwidth.",
        "t3_qname_note": "qname_minimization_risk is always reported as 'unknown'. The tool cannot reliably detect qname minimization using only resolver RCODEs.",
        "t4_note": "T4 only tests three specific entropy patterns (repeating base32, random base32, hex). Real exfil may use different encodings or rates. Heuristic only; OOB logs required for confirmation.",
        "t5_note": "T5 measures received TXT response sizes and performs EDNS buffer-size probes (512/1232/4096). It detects truncation (TC) and whether TCP fallback succeeds for truncated responses. Only TXT is tested for payload capacity; results reflect this host only.",
        "t6_note": "Burst uses 30 concurrent queries (high instantaneous rate, not realistic low-and-slow). Sustained (~1 QPS) is opt-in via --stealth-rate and takes ~90–120 s. Both reflect the assessment host only.",
        "t7_note": "T7 results are from the machine running bounce53 only. Compromised internal hosts (workstations, servers, VDI) frequently have stricter egress controls, host proxies, or different resolvers.",
        "fallback_note": "When OOB records are unreachable or empty, some probes fall back to public domains (google.com, etc.). These may be cached, anycasted, or policy-treated differently than attacker-controlled names.",
    }
    report["remediation"] = {
        "immediate":    "Restrict recursion to internal subnets only (BIND: allow-recursion { 10.0.0.0/8; };). Enable resolver-side rate limiting (BIND rate-limit clause) and cap maximum response sizes / EDNS buffer sizes for untrusted clients.",
        "short_term":   "Block outbound UDP/TCP 53 (and 853/443 for DoH/DoT) from endpoints to the internet except via approved internal resolvers. Enforce at the perimeter firewall or transparent proxy.",
        "medium_term":  "Deploy DNS query logging and detection for high-entropy labels, excessive label lengths (>45-60 chars), high per-client query volumes/rates, and unusually large responses (Zeek, Suricata, or commercial DNS security platforms).",
        "strategic":    "Implement split-horizon DNS with hardened internal resolvers (query minimization + DNSSEC validation). Use RPZ (or equivalent) to sinkhole/rewrite high-risk patterns: long labels, high-entropy subdomains, disallowed record types (e.g. TXT for most clients), and known malicious domains. Block direct public DoH/DoT from endpoints and force all DNS through approved resolvers/proxies. Consider dedicated DNS security/firewall solutions.",
        "mitre_attack": "T1071.004 – Application Layer Protocol: DNS"
    }

    if not raw_queries:
        report.setdefault("limitations_and_caveats", {})["raw_note"] = "This report was generated with --no-raw (or no queries). Full dig commands/stdout/stderr not captured."

    if json_path:
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

    if txt_path:
        # TXT report stays human-focused
        # All field labels capitalized, colons uniformly aligned at LABEL_WIDTH.
        with open(txt_path, "w") as f:
            f.write("bounce53 — DNS Relay Exfiltration Assessment\n\n")
            f.write(f"{'Generated':<{LABEL_WIDTH+2}}: {ts}\n")
            f.write(f"{'Resolver':<{LABEL_WIDTH+2}}: {resolver}\n")
            f.write(f"{'OOB Domain':<{LABEL_WIDTH+2}}: {oob_domain}\n")
            f.write(f"{'Duration':<{LABEL_WIDTH+2}}: {elapsed:.1f}s\n")
            f.write(f"{'Overall':<{LABEL_WIDTH+2}}: {overall}\n\n")
            f.write("FINDINGS\n" + "─" * 50 + "\n")
            for k, v in results.items():
                if isinstance(v, dict):
                    title = TEST_TITLES.get(k, k)
                    f.write(f"\n{title}\n")
                    f.write(f"  {'Severity':<{LABEL_WIDTH}}: {v.get('severity')}\n")
                    f.write(f"  {'Finding':<{LABEL_WIDTH}}: {v.get('finding')}\n")
                    for ek, ev in v.items():
                        if ek not in ("severity", "finding"):
                            disp = _display_label(ek)
                            if ek == "transport" and isinstance(ev, dict):
                                tlines = _format_transport(ev)
                                if tlines:
                                    f.write(f"  {disp:<{LABEL_WIDTH}}: {tlines[0]}\n")
                                    for line in tlines[1:]:
                                        f.write(f"{'':<{LABEL_WIDTH + 2}}: {line}\n")
                                continue
                            if ek == "edns_probes" and isinstance(ev, list):
                                elines = _format_edns_probes(ev)
                                if elines:
                                    f.write(f"  {disp:<{LABEL_WIDTH}}: {elines[0]}\n")
                                    for line in elines[1:]:
                                        f.write(f"{'':<{LABEL_WIDTH + 2}}: {line}\n")
                                continue
                            if ek == "burst" and isinstance(ev, dict):
                                blines = _format_burst(ev)
                                if blines:
                                    f.write(f"  {disp:<{LABEL_WIDTH}}: {blines[0]}\n")
                                    for line in blines[1:]:
                                        f.write(f"{'':<{LABEL_WIDTH + 2}}: {line}\n")
                                continue
                            if ek == "sustained" and isinstance(ev, dict):
                                slines = _format_sustained(ev)
                                if slines:
                                    f.write(f"  {disp:<{LABEL_WIDTH}}: {slines[0]}\n")
                                    for line in slines[1:]:
                                        f.write(f"{'':<{LABEL_WIDTH + 2}}: {line}\n")
                                continue
                            if ek == "reachable" and isinstance(ev, dict):
                                rlines = _format_reachable(ev)
                                if rlines:
                                    f.write(f"  {disp:<{LABEL_WIDTH}}: {rlines[0]}\n")
                                    for line in rlines[1:]:
                                        f.write(f"{'':<{LABEL_WIDTH + 2}}: {line}\n")
                                continue
                            if ek == "oob_check":
                                items = _format_oob_check(ev)
                                if items:
                                    f.write(f"  {'OOB Check':<{LABEL_WIDTH}}: {items[0]}\n")
                                    for item in items[1:]:
                                        f.write(f"{'':<{LABEL_WIDTH + 2}}: {item}\n")
                                continue
                            f.write(f"  {disp:<{LABEL_WIDTH}}: {ev}\n")

            f.write("\n\nREMEDIATION\n" + "─" * 50 + "\n")
            for k, v in report["remediation"].items():
                disp = REMEDIATION_LABELS.get(k, k.replace("_", " ").title())
                f.write(f"\n{disp}\n")
                f.write(f"  {v}\n")

            if "limitations_and_caveats" in report:
                f.write("\n\nLIMITATIONS & CAVEATS\n" + "─" * 50 + "\n")
                for k, v in report["limitations_and_caveats"].items():
                    disp = LIMITATIONS_LABELS.get(k, k.replace("_", " ").title())
                    f.write(f"\n{disp}\n")
                    f.write(f"  {v}\n")

    return json_path, txt_path








# ══════════════════════════════════════════════════════════════════════════════
# 5. Main Entry Point
#    - Parse args
#    - Call the seven test functions (collect results)
#    - Call render_terminal(...)
#    - Call write_report(...)
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # Display a must-have cool banner
    print(r"""
  ▗▖    ▄▄▄  █  ▐▌▄▄▄▄  ▗▞▀▘▗▞▀▚▖▄▄▄▄ ▄▄▄▄
  ▐▌   █   █ ▀▄▄▞▘█   █ ▝▚▄▖▐▛▀▀▘█       █
  ▐▛▀▚▖▀▄▄▄▀      █   █     ▝▚▄▄▖▀▀▀█ ▀▀▀█
  ▐▙▄▞▘                          ▄▄▄█ ▄▄▄█

                               by VoidJarr
""")

    parser = argparse.ArgumentParser(
        description="bounce53 — DNS Relay Exfiltration Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bounce53.py -r 10.0.0.53 -d oob.foobar.com
  python3 bounce53.py -r 192.168.1.1 -d oob.foobar.com -o /tmp/report -f json
  python3 bounce53.py -r 10.10.10.5 -d oob.foobar.com --skip-ratelimit --timeout 8
  python3 bounce53.py -r 10.0.0.53 -d oob.foobar.com --skip-bypass --no-color -o output -f txt
  python3 bounce53.py -r 10.0.0.53 -d oob.foobar.com --no-raw          # smaller JSON, no raw dig details
  python3 bounce53.py -r 10.0.0.53 -d oob.foobar.com --udp-only        # skip TCP sub-probes (TCP on by default for T1-T6/T5)
  python3 bounce53.py -r 10.0.0.53 -d oob.foobar.com --stealth-rate    # T6 sustained low-and-slow after burst

ACCURACY NOTES:
  T3/T4 results use resolver RCODEs as a proxy for "reached authoritative". NXDOMAIN can come from RPZ/policy layers, leading to over-estimation of exfil viability.
  Always cross raw_queries + RCODEs against real OOB logs. T7 (and direct tests) are from this host only.
  TCP tested by default on applicable tests; --udp-only for reduced noise.
  See generated 'limitations_and_caveats' in the JSON report.
        """
    )
    parser.add_argument("-r", "--resolver",   required=True, help="Target corporate DNS resolver IP")
    parser.add_argument("-d", "--oob-domain", required=True, help="OOB domain you control (NS must point to your server)")
    parser.add_argument("-o", "--output",     default="bounce53_report", help="Primary output file name (base name, no extension). Default: bounce53_report")
    parser.add_argument("-f", "--format",     default="txt", help="Output formats to generate, comma-separated (txt and/or json). Default: txt")
    parser.add_argument("--timeout",          type=int, default=5, help="Per-query DNS timeout in seconds (default: 5)")
    parser.add_argument("--skip-ratelimit",   action="store_true", help="Skip T6 — omits burst (and sustained if --stealth-rate)")
    parser.add_argument("--skip-entropy",     action="store_true", help="Skip T4 — avoids sending high-entropy encoded subdomains")
    parser.add_argument("--skip-bypass",      action="store_true", help="Skip T7 — avoids direct egress probes to 8.8.8.8/1.1.1.1/9.9.9.9 and DoH/DoT")
    parser.add_argument("--no-color",         action="store_true", help="Disable ANSI color output (safe for piping/logging)")
    parser.add_argument("--no-raw",           action="store_true", help="Omit raw dig command/output details from the JSON report (smaller files)")
    parser.add_argument("--udp-only",         action="store_true", help="Disable TCP sub-probes for T1–T6 and T5 (response capacity). TCP tested by default.")
    parser.add_argument("--stealth-rate",     action="store_true", help="Enable T6 sustained low-and-slow phase after burst (~60-120 queries at ~1 QPS). Opt-in; adds time.")
    parser.add_argument("--skip-doh-dot",     action="store_true", help="Skip DoH/DoT sub-checks within T7 (UDP/TCP/53 still run).")
    parser.add_argument("--sleep",            type=float, default=0.5, help="Seconds to sleep between tests (default 0.5). Use 0 for fastest runs.")

    args = parser.parse_args()

    no_color = args.no_color

    if not args.resolver or not args.oob_domain:
        parser.error("-r/--resolver and -d/--oob-domain are required")

    if subprocess.run(["which", "dig"], capture_output=True).returncode != 0:
        print("ERROR: 'dig' not found. Install dnsutils (or equivalent).", file=sys.stderr)
        sys.exit(1)

    mode = "TCP: enabled" if not args.udp_only else "TCP: disabled"
    print(f"  {info_label(no_color)} Target: {args.resolver}  |  OOB: {args.oob_domain}  |  Timeout: {args.timeout}s  |  Output: {args.output}  |  {mode}")
    print(f"  {info_label(no_color)} Capture OOB traffic or check dashboard.")

    # Determine output formats (default: only txt)
    fmt = (getattr(args, "format", None) or "txt").lower()
    output_formats = [f.strip() for f in fmt.split(",") if f.strip() in ("txt", "json")] or ["txt"]

    results = {}
    raw_queries: list = []
    start   = time.time()

    test_specs = [
        {"id": "T1_external_relay", "call": lambda: test_external_relay(args.resolver, args.oob_domain, args.timeout, udp_only=args.udp_only, raw_collector=raw_queries)},
        {"id": "T2_record_types", "call": lambda: test_record_types(args.resolver, args.oob_domain, args.timeout, udp_only=args.udp_only, raw_collector=raw_queries)},
        {"id": "T3_label_length", "call": lambda: test_label_length(args.resolver, args.oob_domain, args.timeout, udp_only=args.udp_only, raw_collector=raw_queries)},
        {"id": "T4_entropy", "call": lambda: test_entropy(args.resolver, args.oob_domain, args.timeout, udp_only=args.udp_only, raw_collector=raw_queries), "skip": args.skip_entropy},
        {"id": "T5_response_capacity", "call": lambda: test_response_capacity(args.resolver, args.oob_domain, args.timeout, udp_only=args.udp_only, raw_collector=raw_queries)},
        {"id": "T6_rate_limiting", "call": lambda: test_rate_limiting(args.resolver, args.oob_domain, args.timeout, udp_only=args.udp_only, stealth_rate=args.stealth_rate, raw_collector=raw_queries), "skip": args.skip_ratelimit},
        {"id": "T7_direct_egress", "call": lambda: test_direct_egress(args.resolver, args.timeout, udp_only=args.udp_only, skip_doh_dot=args.skip_doh_dot, raw_collector=raw_queries), "skip": args.skip_bypass, "last": True},
    ]

    for spec in test_specs:
        if spec.get("skip"):
            continue
        r = spec["call"]()
        results[spec["id"]] = r
        render_test(spec["id"], r, args.oob_domain, no_color=no_color)
        if not spec.get("last"):
            time.sleep(args.sleep)

    # stash raw for the report writer (write_report pops _raw_queries)
    if raw_queries:
        results["_raw_queries"] = raw_queries

    raw_count = len(raw_queries)

    elapsed = time.time() - start
    json_path, txt_path = write_report(results, args.resolver, args.oob_domain, args.output, elapsed, args, output_formats=output_formats)
    render_terminal(results, args.resolver, args.oob_domain, elapsed, args, no_color=no_color, json_path=json_path, txt_path=txt_path, raw_count=raw_count)


if __name__ == "__main__":
    main()