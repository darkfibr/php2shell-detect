# php2shell-detect

Defensive detection toolkit for **php2shell** — the `session.upload_progress`
heap use-after-free pair **CVE-2026-109618 / CVE-2026-109619** (CVSS v4.0 9.2
each, PHP 5.4 through 8.5). A PHP emergency release was announced for
2026-10-21 14:00 UTC; a public PoC and a full mechanics writeup are already
circulating, and scanning started *before* the patch.

Everything here is **read-only and offline**: it scans evidence you already
have (logs, captured bodies, files on disk). Nothing phones home, nothing
sends traffic, nothing is exploited.

## Why a shape scanner, not just an indicator list

The public PoC is polite — it announces itself:

```
User-Agent: php2shell-109619          (or -109618)
Content-Type: multipart/form-data; boundary=B7kQpoc619
```

Real weapons won't. But the vulnerability mechanics force a request **shape**
that survives UA stripping. The bug: PHP's upload-progress tracking caches two
raw bucket pointers into live HashTables
(`post_bytes_processed`, `current_file_bytes_processed`). On the second
`update()` (post `min_freq`/stall), the session re-read re-initializes the
decoded tree and the cached pointers dangle. The reclaim recipe from the
public writeup: spray packed array form fields (`t[]`) — **149 elements lands
nTableSize 256 → 320-byte string bins** — then steer the stale-pointer
read/write into a forged `zend_fcall_info` / `zend_internal_function` →
`zend_call_function` → `system()`.

Which means every attempt must contain, in one POST body to a `.php` endpoint:

1. `name="PHP_SESSION_UPLOAD_PROGRESS"` — no progress field, no primitive;
2. ≳100 identical array-form parts — the reclaim spray.

That combination is an exploit attempt **regardless of headers**. It is the
ATTEMPT-HIGH tier of `php2shell_scan.py` and the v2 Suricata/Snort rules.

## What's in the box

| File | What it does |
|---|---|
| `php2shell_scan.py` | Scan access logs and captured request bodies for attempts, UA-independent, four confidence tiers |
| `php2shell_check.py` | Estate checker: is PHP exposed, is `session.upload_progress` enabled, version in affected range; non-destructive, `--fixed-map` when official fixed versions land |
| `check_estate.sh` | One-command local sweep over every web-log directory it can find |
| `rules/suricata.rules` | v1 indicator rules + v2 mechanics-shape rules (UA-independent) |
| `rules/snort.rules` | v1 UA rules + v2 Snort 3 body-shape rules |
| `signatures/php2shell_signatures.txt` | Full fingerprint list with regexes, for log/pcap/proxy grep |
| `signatures/php2shell_poc.yar` | YARA rule for the public PoC scripts |
| `fixtures/` | Synthetic test inputs — including a **clean-UA mechanics-shape body** the scanner must catch and a benign form it must not |

## Usage

```bash
# scan web access logs (nginx/apache combined, JSON lines)
python3 php2shell_scan.py --access-log /var/log/nginx/access.log*

# scan captured request bodies (mod_security audit, Caddy/mitm dumps)
python3 php2shell_scan.py --body-log modsec_audit.log

# both, with a JSON report
python3 php2shell_scan.py --access-log a.log --body-log b.log --json out.json

# check a host estate (local dirs / config exposure)
python3 php2shell_check.py --local /var/www
./check_estate.sh          # local log sweep, one command

# regression-test the scanner against the fixtures
python3 php2shell_scan.py --access-log fixtures/access_hit.log \
       --body-log fixtures/body_shape_clean_ua.txt --quiet
```

## Tiers

| Tier | Meaning | Action |
|---|---|---|
| `COMPROMISE-CONFIRMED` | `JACKALPOC` success marker in a captured body/response | Treat the host as compromised. Pull it, image it, rotate everything it could reach. |
| `ATTEMPT-HIGH` | Mechanics shape: progress field + ≥100 array-form parts | Exploit attempt with the UA stripped. Block the source, check the host for follow-on. |
| `ATTEMPT-KNOWN` | PoC UA / boundary strings | Script-kiddie wave. Block, monitor. |
| `CONTEXT` | Weaker shape (progress field, small sprays) | Investigate if clustered in time. |

**A log hit is an attempt, not a compromise.** Confirm compromise only via the
`JACKALPOC` marker or host evidence. Conversely, absence of hits in *access
logs alone* proves little — nginx's default format never records
`Content-Type` or bodies, so shape attempts are invisible there. Run the
estate check and, if you have edge capture, the v2 rules.

## Notes on the estate check

`php2shell_check.py` ships with an **empty** fixed-version table: no official
fixed versions existed at time of writing, and inventing them is worse than
shipping none. Feed it `--fixed-map versions.json`
(`{"8.4": "8.4.5", ...}`) once PHP publishes the releases.

Also: `magic_quotes_gpc` does nothing here (removed in PHP 5.4). If a guide
suggests it as a mitigation, the guide is older than the bug class.

## Sources / provenance

- CVE-2026-109618 / CVE-2026-109619 — public PoC bundle (`poc0_109618.py`,
  `poc1_109619.py`, `php_up_framework.py`) and the public mechanics writeup,
  both circulating since 2026-10-21.
- Observed wave: self-identifying UAs `php2shell-109618/109619` scanning
  arbitrary `.php` endpoints; UA number reportedly incremented per request.
- No samples, payloads, or indicators were downloaded in building this
  toolkit; signatures are derived from the published request shape.

## License

MIT — see `LICENSE`.
