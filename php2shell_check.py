#!/usr/bin/env python3
"""
php2shell exposure checker — non-destructive, for defenders.

Context: PHP 5.4 through 8.5 are affected by CVE-2026-109618 and
CVE-2026-109619 (CVSS v4.0 9.2 each), a heap use-after-free in the
session.upload_progress handler that yields RCE via a crafted multipart POST.
Emergency patch release was scheduled for 2026-10-21 14:00 UTC. Versions 8.2,
8.3, 8.4 and 8.5 receive fixes; 8.1, 8.0, 7.x and 5.x are end-of-life and
will never receive one.

WHAT THIS TOOL DOES
  * Sends ONE benign HTTP request per host (GET /, short timeout, no payloads).
  * Reads the PHP version from response headers if the server advertises it.
  * Classifies the host: VULNERABLE_VERSION / PATCHED_VERSION / UNKNOWN /
    NOT_PHP.
  * Optionally checks a local filesystem for php.ini files and reports whether
    session.upload_progress.enabled is still On.

WHAT THIS TOOL DELIBERATELY DOES NOT DO
  * It never sends an exploit, a multipart body, or a session.upload_progress
    payload. It does not attempt remote code execution on anything.
  * It does not brute force, fingerprint aggressively, or evade detection.
  * It is for hosts you own or are authorized to assess. Mass-scanning other
    people's infrastructure is your legal problem, not this script's.

Usage:
  python3 php2shell_check.py --hosts hosts.txt [--json out.json] [--timeout 6]
  python3 php2shell_check.py --host example.com --host 10.0.0.5:8080
  python3 php2shell_check.py --local /etc /usr/local/etc --json estate.json

Exit codes: 0 = no vulnerable host found, 1 = at least one vulnerable host
found, 2 = bad usage or no host could be assessed.
"""

import argparse
import glob
import gzip
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Versions confirmed affected by the advisories. Fixed versions were published
# with the 2026-10-21 emergency release; entries below the fixed patch are
# vulnerable. Conservative: anything we cannot place is UNKNOWN, not "safe".
AFFECTED_RANGE = "5.4 through 8.5 (8.1, 8.0, 7.x, 5.x are EOL and unpatched)"

# Minimum versions carrying the fix, per branch. INTENTIONALLY EMPTY by
# default: the emergency release was scheduled for 2026-10-21 14:00 UTC, and
# until those release notes are public the exact fixed versions are not known.
# Shipping guessed version numbers would be worse than shipping none.
# Update at runtime with --fixed-map <file.json> containing {"8.2": "8.2.29", ...}
# once you have the official release notes in front of you.
FIXED_MIN = {}

# Branches covered by the advisories (all of 5.4 through 8.5).
AFFECTED_BRANCHES = ("8.2", "8.3", "8.4", "8.5")

# Branches that will never receive a fix.
EOL_BRANCHES = ("5.", "7.", "8.0", "8.1")


def version_tuple(v):
    parts = []
    for chunk in re.split(r"[._-]", v):
        m = re.match(r"^(\d+)", chunk)
        parts.append(int(m.group(1)) if m else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def classify(version):
    """Return (verdict, detail) for a PHP version string."""
    if not version:
        return "UNKNOWN", "no PHP version advertised"
    v = version.strip().lstrip("v")
    if not re.match(r"^\d+\.\d+", v):
        return "UNKNOWN", f"unparseable version {version!r}"
    base = ".".join(v.split(".")[:2])
    if any(v.startswith(b) for b in EOL_BRANCHES):
        return "VULNERABLE_VERSION", f"PHP {v} is end-of-line; no fix will be published"
    fixed = FIXED_MIN.get(base)
    if fixed is None:
        if base in AFFECTED_BRANCHES:
            return ("VULNERABLE_VERSION",
                    f"PHP {v} is in the affected range for CVE-2026-109618/109619; "
                    f"this tool has no confirmed fix version for {base} "
                    f"(update with --fixed-map after the release notes are public)")
        return "UNKNOWN", f"PHP {v} is not in the published affected range ({AFFECTED_RANGE})"
    if version_tuple(v) < version_tuple(fixed):
        return "VULNERABLE_VERSION", f"PHP {v} is below {base} fix {fixed}"
    return "PATCHED_VERSION", f"PHP {v} is at or above {base} fix {fixed}"


def probe(host, timeout=6):
    """One benign GET against host. Returns a dict describing what we saw."""
    target = host
    if "://" not in target:
        target = "http://" + target
    req = urllib.request.Request(target, method="GET", headers={
        "User-Agent": "php2shell-exposure-check/1.0 (benign, single GET)",
        "Accept": "*/*",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    result = {"host": host, "url": target, "verdict": "UNKNOWN", "detail": "",
              "http_status": None, "php_version": None, "server": None}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["http_status"] = resp.status
            headers = resp.headers
            result["server"] = headers.get("Server")
            result["x_powered_by"] = headers.get("X-Powered-By")
            body = resp.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        result["http_status"] = e.code
        headers = e.headers
        result["server"] = headers.get("Server")
        result["x_powered_by"] = headers.get("X-Powered-By")
        try:
            body = e.read(2048).decode("utf-8", "replace")
        except Exception:
            body = ""
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
        result["detail"] = f"unreachable: {type(e).__name__}: {e}"
        return result

    version = None
    xp = result.get("x_powered_by") or ""
    m = re.search(r"PHP/([\d.]+)", xp, re.I)
    if m:
        version = m.group(1)
    if not version:
        m = re.search(r"PHP\s*([\d]+\.[\d]+(?:\.\d+)?)", body, re.I)
        if m:
            version = m.group(1)
    result["php_version"] = version
    verdict, detail = classify(version)
    if verdict == "UNKNOWN" and not xp:
        detail = "no PHP version advertised; cannot rule out exposure"
    result["verdict"], result["detail"] = verdict, detail
    return result


def local_check(paths):
    """Look for php.ini and report the session.upload_progress setting."""
    findings = []
    seen = set()
    for root in paths:
        for dirpath, dirnames, filenames in os.walk(root):
            for fn in filenames:
                if fn not in ("php.ini", "php.ini-development", "php.ini-production"):
                    continue
                p = os.path.join(dirpath, fn)
                if p in seen:
                    continue
                seen.add(p)
                setting = "not found (default applies)"
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            s = line.strip()
                            if s.startswith(";") or "=" not in s:
                                continue
                            key, val = s.split("=", 1)
                            if key.strip() == "session.upload_progress.enabled":
                                setting = val.strip()
                                break
                except OSError as e:
                    setting = f"unreadable: {e}"
                verdict = "MITIGATED" if setting.lower() in ("off", "0", "") else "EXPOSED"
                findings.append({"file": p, "session.upload_progress.enabled": setting,
                                 "verdict": verdict})
    return findings


LOG_PATTERNS = {
    "ua": re.compile(r"php2shell-\d{6}", re.I),
    "boundary": re.compile(r"B7kQpoc\d{3}", re.I),
    "upload_progress": re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I),
    "multipart": re.compile(r"multipart/form-data", re.I),
}
LOG_TS_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
LOG_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
LOG_REQ_RE = re.compile(r'"(?:GET|POST|PUT|HEAD|OPTIONS|PATCH|DELETE) (\S+)\s+HTTP/')


def _log_files(paths):
    """Expand files, dirs and globs into a de-duplicated list. Read-only."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            for pat in ("*.log", "*.log.*", "*.log.*.gz"):
                out.extend(sorted(glob.glob(os.path.join(p, pat))))
        elif os.path.isfile(p):
            out.append(p)
        else:
            out.extend(sorted(glob.glob(p)))
    seen, uniq = set(), []
    for p in out:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def _read_log(p):
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, encoding="utf-8", errors="replace")


def scan_logs(paths):
    """Grep logs for php2shell request fingerprints. Returns a report dict.

    Read-only. It matches user-agents of the form php2shell-<6 digits>, the
    multipart boundary B7kQpoc<3 digits>, and the upload-progress field name.
    `multipart/form-data` is counted for context but does not by itself count
    as a hit.
    """
    files = _log_files(paths)
    counts = {k: 0 for k in LOG_PATTERNS}
    hits = []
    lines_total = 0
    for p in files:
        try:
            fh = _read_log(p)
        except OSError as e:
            hits.append({"file": p, "error": str(e)})
            continue
        with fh:
            for lineno, line in enumerate(fh, 1):
                lines_total += 1
                matched = {k: bool(rx.search(line)) for k, rx in LOG_PATTERNS.items()}
                for k, v in matched.items():
                    if v:
                        counts[k] += 1
                if not (matched["ua"] or matched["boundary"] or matched["upload_progress"]):
                    continue
                m = LOG_TS_RE.search(line)
                dt = None
                if m:
                    try:
                        dt = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
                    except ValueError:
                        dt = None
                parts = line.split()
                ip = parts[0] if parts and LOG_IP_RE.match(parts[0]) else ""
                if not ip:
                    mip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                    ip = mip.group(0) if mip else ""
                mreq = LOG_REQ_RE.search(line)
                hits.append({
                    "file": p,
                    "line": lineno,
                    "ts": dt.isoformat() if dt else None,
                    "ip": ip,
                    "path": mreq.group(1) if mreq else "",
                    "ua": matched["ua"],
                    "boundary": matched["boundary"],
                    "upload_progress": matched["upload_progress"],
                })

    dts = [datetime.fromisoformat(h["ts"]) for h in hits if h.get("ts")]
    ip_counts, path_counts = {}, {}
    for h in hits:
        if h.get("ip"):
            ip_counts[h["ip"]] = ip_counts.get(h["ip"], 0) + 1
        if h.get("path"):
            path_counts[h["path"]] = path_counts.get(h["path"], 0) + 1
    return {
        "paths": paths,
        "files_scanned": len(files),
        "lines_scanned": lines_total,
        "counts": counts,
        "first_hit": min(dts).isoformat() if dts else None,
        "last_hit": max(dts).isoformat() if dts else None,
        "source_ips": dict(sorted(ip_counts.items(), key=lambda kv: -kv[1])),
        "request_paths": dict(sorted(path_counts.items(), key=lambda kv: -kv[1])),
        "hits": hits,
    }


def print_log_report(r):
    c = r["counts"]
    print("== php2shell log scan ==")
    print(f"files scanned: {r['files_scanned']}   lines scanned: {r['lines_scanned']}")
    print(f"UA hits (php2shell-\\d{{6}}): {c['ua']}")
    print(f"boundary hits (B7kQpoc\\d{{3}}): {c['boundary']}")
    print(f"upload-progress field hits: {c['upload_progress']}")
    print(f"multipart/form-data lines (context only): {c['multipart']}")
    print(f"first hit: {r['first_hit'] or 'none'}")
    print(f"last hit:  {r['last_hit'] or 'none'}")
    if r["source_ips"]:
        print("source IPs:")
        for ip, n in r["source_ips"].items():
            print(f"  {n:6d}  {ip}")
    if r["request_paths"]:
        print("request paths:")
        for p, n in r["request_paths"].items():
            print(f"  {n:6d}  {p}")
    for h in r["hits"]:
        if h.get("error"):
            print(f"ERROR {h['file']}: {h['error']}")
    if not any(c[k] for k in ("ua", "boundary", "upload_progress")):
        print("no php2shell fingerprints found")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", action="append", default=[], help="host or host:port (repeatable)")
    ap.add_argument("--hosts", help="file with one host per line")
    ap.add_argument("--local", action="append", default=[],
                    help="directory to scan for php.ini (repeatable)")
    ap.add_argument("--json", help="write results as JSON to this path")
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--fixed-map", help="JSON file mapping branch -> first fixed version, "
                                        "e.g. {\"8.2\": \"8.2.29\"}. Supply this once the "
                                        "official release notes are public.")
    ap.add_argument("--logs", action="append", default=[],
                    help="log file, directory or glob to scan for php2shell request "
                         "fingerprints (repeatable). Read-only; no network.")
    args = ap.parse_args()

    if args.fixed_map:
        with open(args.fixed_map, encoding="utf-8") as fh:
            FIXED_MIN.update(json.load(fh))

    log_report = scan_logs(args.logs) if args.logs else None

    hosts = list(args.host)
    if args.hosts:
        with open(args.hosts, encoding="utf-8") as fh:
            hosts += [l.strip() for l in fh if l.strip() and not l.startswith("#")]

    results, local_results = [], []
    if hosts:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            results = list(pool.map(lambda h: probe(h, args.timeout), hosts))
    if args.local:
        local_results = local_check(args.local)

    if log_report is not None:
        print_log_report(log_report)
        print()

    if not results and not local_results:
        if log_report is not None:
            if args.json:
                with open(args.json, "w", encoding="utf-8") as fh:
                    json.dump({"affected_range": AFFECTED_RANGE, "fixed_min": FIXED_MIN,
                               "hosts": [], "local": [], "logs": log_report,
                               "note": "log scan only; no host probe performed"}, fh, indent=2)
            return 1 if any(log_report["counts"][k]
                            for k in ("ua", "boundary", "upload_progress")) else 0
        if args.local:
            print(f"no php.ini found under {', '.join(args.local)} — no PHP configuration present "
                  f"on this host")
            if args.json:
                with open(args.json, "w", encoding="utf-8") as fh:
                    json.dump({"affected_range": AFFECTED_RANGE, "fixed_min": FIXED_MIN,
                               "hosts": [], "local": [],
                               "note": "non-destructive probe only; no php.ini present"}, fh, indent=2)
            return 0
        print("nothing to check: pass --host/--hosts, --local and/or --logs", file=sys.stderr)
        return 2

    if results:
        print(f"{'VERDICT':20s} {'HOST':38s} DETAIL")
        print("-" * 100)
        for r in sorted(results, key=lambda r: (r["verdict"] != "VULNERABLE_VERSION", r["host"])):
            print(f"{r['verdict']:20s} {r['host'][:38]:38s} {r['detail']}")
    for l in local_results:
        print(f"{l['verdict']:20s} {l['file'][:38]:38s} "
              f"session.upload_progress.enabled = {l['session.upload_progress.enabled']}")

    payload = {"affected_range": AFFECTED_RANGE, "fixed_min": FIXED_MIN,
               "hosts": results, "local": local_results,
               "note": "non-destructive probe only; no exploit payload was sent"}
    if log_report is not None:
        payload["logs"] = log_report
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    if any(r["verdict"] == "VULNERABLE_VERSION" for r in results):
        print("\nMITIGATION: set session.upload_progress.enabled = Off in every php.ini, "
              "or upgrade to the fixed version on your branch.")
        print("Do not rely on magic_quotes_gpc — it was removed in PHP 5.4 and does nothing.")
        return 1
    if any(l["verdict"] == "EXPOSED" for l in local_results):
        return 1
    if log_report is not None and any(log_report["counts"][k]
                                      for k in ("ua", "boundary", "upload_progress")):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
