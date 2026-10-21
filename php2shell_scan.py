#!/usr/bin/env python3
"""
php2shell_scan.py — attempt scanner for CVE-2026-109618 / CVE-2026-109619.

Detects EXPLOIT ATTEMPTS in evidence you already have (access logs, request-body
captures). Never sends traffic, never touches a host, never writes anywhere but
its own output. Pure stdlib, Python 3.8+.

Why a "shape" scanner and not just an indicator list
----------------------------------------------------
The public PoC is polite: it announces itself (User-Agent: php2shell-109618,
boundary=B7kQpoc619). Real weapons won't. But the vulnerability mechanics are
public now (see README), and they force a request *shape* that survives UA
stripping:

  1. multipart/form-data POST to a .php endpoint,
  2. a PHP_SESSION_UPLOAD_PROGRESS field (the bug lives in upload progress
     tracking — without it there is no primitive),
  3. a spray of >= ~100 identical array-form parts (name="t[]" in the PoC;
     149 elements is the count that lands a packed array in the freed
     320-byte string bins — nTableSize 256),
  4. optionally a mid-body stall (the PoC pauses ~1.35s to force the second
     update() that dangles the cached bucket pointers).

A request matching 1+2+3 is an exploit attempt regardless of UA, headers, or
path. That is the ATTEMPT-HIGH tier below.

Tiers
-----
  COMPROMISE-CONFIRMED  "JACKALPOC" (PoC success marker) in a captured body
                         or response — if you see this, treat the host as
                         compromised and pull it.
  ATTEMPT-HIGH          mechanics shape: PHP_SESSION_UPLOAD_PROGRESS + >=100
                         identical array-form parts (UA-independent).
  ATTEMPT-KNOWN         known PoC UA / boundary strings.
  CONTEXT               weaker signals — post to .php + multipart + smaller
                         array sprays; investigate if clustered in time.

Usage
-----
  python3 php2shell_scan.py --access-log /var/log/nginx/access.log*
  python3 php2shell_scan.py --body-log modsec_audit.log
  python3 php2shell_scan.py --access-log a.log --body-log b.log --json out.json

Body logs: mod_security audit logs, Caddy/Traefik JSON logs that include
request bodies, mitmproxy flow dumps, or any text file containing raw
multipart request bodies.

Exit codes: 0 = nothing above CONTEXT, 1 = at least one hit (any tier), 2 = error.
"""

import argparse
import glob
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone

# --- indicators (from the public PoC bundle + observed wave) -----------------

UA_RE = re.compile(r"(?i)php2shell-\d{6}")
BOUNDARY_RE = re.compile(r"(?i)boundary=B7kQpoc\d{3}")
PROGRESS_FIELD_RE = re.compile(r'(?i)name="PHP_SESSION_UPLOAD_PROGRESS"')
JACKALPOC_RE = re.compile(r"(?i)JACKALPOC")
ARRAY_PART_RE = re.compile(r'(?i)name="([a-z0-9_]*\[\])"')
MULTIPART_RE = re.compile(r"(?i)content-type:\s*multipart/form-data")
POST_PHP_RE = re.compile(r'(?i)(POST|post)\s+[^\s"]*\.php')

SPRAY_THRESHOLD = 100      # PoC uses 149; 100 keeps margin for variants
SPRAY_CONTEXT_MIN = 20     # below this, arrays are probably a normal form

NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" '
    r"(?P<status>\d{3}) (?P<size>\S+)(?: \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\")?"
)


def expand(paths):
    for p in paths:
        for m in sorted(glob.glob(p)) or [p]:
            yield m


def tier_of(*, ua_text="", body_text=""):
    """Evaluate one record's evidence. Returns (tier, reason) or None."""
    if JACKALPOC_RE.search(body_text or ""):
        return "COMPROMISE-CONFIRMED", "JACKALPOC success marker in captured body/response"
    if PROGRESS_FIELD_RE.search(body_text or ""):
        counts = Counter(m.group(1).lower() for m in ARRAY_PART_RE.finditer(body_text or ""))
        top_name, top = (counts.most_common(1)[0] if counts else ("", 0))
        if top >= SPRAY_THRESHOLD:
            return ("ATTEMPT-HIGH",
                    f"upload-progress field + {top}x array-form part name=\"{top_name}\" "
                    f"(>= {SPRAY_THRESHOLD}: reclaim spray shape)")
    if UA_RE.search(ua_text or ""):
        return "ATTEMPT-KNOWN", "PoC user-agent string"
    if BOUNDARY_RE.search(ua_text or "") or BOUNDARY_RE.search(body_text or ""):
        return "ATTEMPT-KNOWN", "PoC multipart boundary"
    # context tier
    if PROGRESS_FIELD_RE.search(body_text or ""):
        counts = Counter(m.group(1).lower() for m in ARRAY_PART_RE.finditer(body_text or ""))
        top = counts.most_common(1)[0][1] if counts else 0
        if top >= SPRAY_CONTEXT_MIN:
            return ("CONTEXT",
                    f"upload-progress field + {top}x array-form parts "
                    f"(< {SPRAY_THRESHOLD}: shape incomplete or variant)")
    if UA_RE.search(body_text or ""):
        return "CONTEXT", "partial UA match"
    return None


def scan_access_log(path):
    """nginx/apache combined+common; JSON-lines with ua/request fields."""
    hits = []
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError as e:
        return [{"file": path, "tier": "ERROR", "reason": str(e)}], 0
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    j = None
                if isinstance(j, dict):
                    req = j.get("request") or ""
                    ua = j.get("user_agent") or j.get("ua") or ""
                    t = tier_of(ua_text=f"{ua} {req}", body_text=req)
                    if t:
                        hits.append({"file": path, "line": n, "tier": t[0],
                                     "reason": t[1], "raw": line[:300]})
                continue
            m = NGINX_RE.match(line)
            if m:
                t = tier_of(ua_text=f"{m.group('ua') or ''} {m.group('req')}",
                            body_text="")
                if t:
                    hits.append({"file": path, "line": n, "tier": t[0],
                                 "reason": t[1],
                                 "ip": m.group("ip"), "ts": m.group("ts"),
                                 "request": m.group("req")[:200]})
            else:
                t = tier_of(ua_text=line, body_text="")
                if t:
                    hits.append({"file": path, "line": n, "tier": t[0],
                                 "reason": t[1], "raw": line[:300]})
    return hits, n


def scan_body_log(path):
    """Whole-file body evidence: mod_sec audit, caddy json bodies, dumps."""
    hits, n = [], 0
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError as e:
        return [{"file": path, "tier": "ERROR", "reason": str(e)}], 0
    with fh:
        # mod_security audit logs are delimited by --HHHHHHHH--A-- sections;
        # otherwise fall back to generous fixed windows.
        data = fh.read()
    if "--A--" in data:
        chunks = re.split(r"--[0-9A-Fa-f]{6,}--", data)
    else:
        # windows of ~64KB so a spray inside a huge dump still localizes
        chunks = [data[i:i + 65536] for i in range(0, len(data), 65536)] or [""]
    for n, chunk in enumerate(chunks, 1):
        t = tier_of(ua_text=chunk, body_text=chunk)
        if t:
            hits.append({"file": path, "chunk": n, "tier": t[0], "reason": t[1]})
    return hits, n


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--access-log", action="append", default=[],
                    help="access log (nginx/apache combined, JSON lines); glob ok; repeatable")
    ap.add_argument("--body-log", action="append", default=[],
                    help="captured bodies (mod_sec audit, caddy/mitm dumps); glob ok; repeatable")
    ap.add_argument("--json", help="write full report as JSON to this path")
    ap.add_argument("--quiet", action="store_true", help="only print summary")
    a = ap.parse_args()

    if not a.access_log and not a.body_log:
        print("nothing to scan: pass --access-log and/or --body-log", file=sys.stderr)
        return 2

    report = {"tool": "php2shell_scan.py",
              "generated_utc": datetime.now(timezone.utc).isoformat(),
              "tiers_seen": Counter(), "files": {}, "hits": []}
    errors = 0
    for p in expand(a.access_log):
        hits, lines = scan_access_log(p)
        errors += sum(1 for h in hits if h["tier"] == "ERROR")
        report["files"][p] = {"kind": "access", "lines": lines,
                              "hits": len([h for h in hits if h["tier"] != "ERROR"])}
        report["hits"] += hits
    for p in expand(a.body_log):
        hits, chunks = scan_body_log(p)
        errors += sum(1 for h in hits if h["tier"] == "ERROR")
        report["files"][p] = {"kind": "body", "chunks": chunks,
                              "hits": len([h for h in hits if h["tier"] != "ERROR"])}
        report["hits"] += hits

    for h in report["hits"]:
        report["tiers_seen"][h["tier"]] += 1

    order = {"COMPROMISE-CONFIRMED": 0, "ATTEMPT-HIGH": 1, "ATTEMPT-KNOWN": 2,
             "CONTEXT": 3, "ERROR": 4}
    report["hits"].sort(key=lambda h: order.get(h["tier"], 9))

    if not a.quiet:
        for h in report["hits"]:
            loc = h.get("line") or h.get("chunk")
            print(f"[{h['tier']}] {h['file']}:{loc} — {h['reason']}")
            if h.get("ip"):
                print(f"          ip={h['ip']} ts={h['ts']} req={h.get('request')}")
    tiers = dict(report["tiers_seen"])
    print(f"\nsummary: {tiers or 'no hits'}; "
          f"files scanned: {len(report['files'])}; errors: {errors}")
    if tiers.get("COMPROMISE-CONFIRMED"):
        print("!! JACKALPOC marker found — treat the host as compromised and pull it.")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({**report, "tiers_seen": tiers}, f, indent=2, default=str)
        print(f"wrote {a.json}")

    worst = min((order.get(h["tier"], 9) for h in report["hits"]), default=9)
    return 0 if worst >= 4 or not report["hits"] else 1


if __name__ == "__main__":
    sys.exit(main())
