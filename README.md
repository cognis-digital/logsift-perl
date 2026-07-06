# logsift

**Dependency-free log triage & SIEM-ready detection — in pure Perl 5.**

[![ci](https://github.com/cognis-digital/logsift-perl/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/logsift-perl/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-Perl%205-informational)
![deps](https://img.shields.io/badge/deps-core%20only-2ea043)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

SOC and DFIR analysts drown in raw logs. `logsift` is a fast **first-pass triage** tool:
it parses the log formats you actually have, runs a battery of streaming detectors,
and emits **SIEM-ready findings** (JSON, NDJSON, CEF, or a human table). No CPAN
dependencies — `JSON::PP` and `IO::Uncompress::Gunzip` ship with core Perl 5.14+.
It streams input line-by-line (never slurps), so a multi-gigabyte log costs constant memory.

```console
$ perl logsift.pl --format text /var/log/auth.log
logsift 2.0.0
  events scanned : 84213
  auth failures  : 1102 from 7 source(s)
  by severity    : 2=1102 6=83111

TYPE               SEV    SOURCE           COUNT    EVIDENCE
------------------------------------------------------------------------------
brute_force        2      203.0.113.9      842      842 failed logins from 203.0.113.9
                                         ATT&CK T1110.001
password_spray     2      203.0.113.9      31       203.0.113.9 attempted 31 distinct users
                                         ATT&CK T1110.003

2 finding(s).
```

## Why it's useful

- **Multi-format**: OpenSSH/PAM auth, **syslog RFC 3164 & RFC 5424**, **Apache/Nginx**
  combined access logs, and **JSON** logs — with `--format-in auto` detection per line.
- **Real detectors**, not just keyword grep:
  - `brute_force` — many failed logins from one source IP
  - `password_spray` — one IP against many distinct users
  - `http_scan` — one IP requesting many distinct paths
  - `http_error_burst` — a burst of 4xx/5xx from one IP
  - `rate_spike` — time buckets that exceed `mean + N·stddev` of the event rate (baseline reported)
  - `rare_signature` — Drain-lite log templating; reports message signatures seen `≤ K` times
- **MITRE ATT&CK tags — honest.** Findings carry a technique ID **only where the mapping
  is defensible** (`brute_force → T1110.001`, `password_spray → T1110.003`, valid-account
  bursts → `T1078`). Generic spikes and rare signatures are deliberately **left untagged**.
- **SIEM-ready output**: JSON, NDJSON (stream), **CEF** (ArcSight Common Event Format), text.
- **CI-friendly exit contract**: `0` clean, `2` findings, `1` error.

## Install

```bash
# POSIX (Linux/macOS): copies logsift + lib to /usr/local
sudo ./install.sh

# Windows (PowerShell)
./install.ps1

# Or just run it in place — no build step:
perl logsift.pl sample.log
```

Requires Perl **5.14+** (for core `JSON::PP`). Tested on 5.34.

## Usage

```
logsift [options] FILE [FILE...]      # .gz auto-detected, multiple files OK
cat auth.log | logsift -              # read stdin

Input:
  --format-in NAME   auto|json|syslog3164|syslog5424|nginx|apache|generic
  --since SPEC       only events at/after SPEC (epoch or YYYY-MM-DDTHH:MM:SS)
  --until SPEC       only events at/before SPEC

Output:
  --format NAME      json (default) | ndjson | cef | text

Detectors / thresholds:
  --fail-threshold N   brute-force min failed logins per IP (5)
  --spray-threshold N  spray min distinct users per IP (5)
  --scan-paths N       http scan min distinct paths per IP (15)
  --error-burst N      http error-burst min 4xx/5xx per IP (20)
  --rare-max N         report signatures seen <= N times (2)
  --bucket SECONDS     rate-spike time bucket width (60)
  --spike-sigma F      rate-spike threshold = mean + F*stddev (3.0)
  --allowlist-ip IP    suppress detections for this IP (repeatable)

  -h, --help           full help    --version    print version
```

Full man page: `perldoc logsift.pl`. See [`docs/USAGE.md`](docs/USAGE.md) for recipes.

### Examples

```bash
# SSH brute force, human table
perl logsift.pl --format text examples/logs/auth.log

# Nginx path-scanning, JSON
perl logsift.pl --format-in nginx examples/logs/nginx-access.log

# Ship findings to a SIEM as CEF
perl logsift.pl --format cef /var/log/auth.log | nc siem.internal 514

# Only the last 24h, ignore your jump host
perl logsift.pl --since 2026-06-22T00:00:00 --allowlist-ip 10.0.0.5 auth.log
```

Runnable demos in [`examples/`](examples/) — `sh examples/run_all.sh` runs all five and exits 0.

## Benchmark (honest, reproducible)

`bench/bench.pl` generates a synthetic auth log, then times a full parse+detect pass:

```
$ perl bench/bench.pl 500000
  perl        : 5.34.0
  os/arch     : x86_64-msys-thread-multi
  lines       : 500000
  throughput  : ~34,000 lines/sec
```

**Measured: ~34,000 lines/sec (parse + all detectors)** on **Perl 5.34, Windows 10, x86_64**.
Reproduce with `perl bench/bench.pl [LINES]` — your number will vary by hardware.

## Architecture

Parsers → normalized event → streaming detectors → renderers.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the event schema, the Drain-lite
templating algorithm, and the full ATT&CK mapping table.

## Standards

- **RFC 3164** (BSD syslog) and **RFC 5424** (syslog, PRI-derived severity)
- **CEF** (ArcSight Common Event Format) output for SIEM ingest
- **MITRE ATT&CK** technique tagging (T1110.001 / T1110.003 / T1078)

## Scope

Defensive / detection / triage only. `logsift` reads logs and reports findings; it takes
no action against any host. See [`DISCLAIMER.md`](DISCLAIMER.md).

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
