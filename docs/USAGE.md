# logsift usage recipes

`logsift` reads logs and prints findings. Exit code: `0` clean, `2` findings, `1` error.

## Input

```bash
perl logsift.pl auth.log                 # a file
perl logsift.pl a.log b.log c.log        # several files, merged
perl logsift.pl archive.log.gz           # .gz decompressed on the fly
cat auth.log | perl logsift.pl -         # stdin
journalctl -u ssh | perl logsift.pl -    # a live pipe
```

### Choosing a parser

`--format-in auto` (default) detects the format per line. Force one when auto-detect
guesses wrong (e.g. an unusual access-log layout):

```bash
perl logsift.pl --format-in syslog5424 app.log
perl logsift.pl --format-in nginx      access.log
perl logsift.pl --format-in json       events.ndjson
```

### Time windows

`--since` / `--until` accept an epoch integer or `YYYY-MM-DDTHH:MM:SS`. Lines without a
parseable timestamp are always kept (fail-open, so you never silently drop un-timestamped data):

```bash
perl logsift.pl --since 2026-06-22T00:00:00 --until 2026-06-22T23:59:59 auth.log
perl logsift.pl --since 1750000000 auth.log
```

## Output

```bash
perl logsift.pl --format text  auth.log   # human table + severity histogram
perl logsift.pl --format json  auth.log   # one canonical document (default)
perl logsift.pl --format ndjson auth.log  # one finding per line, for streaming
perl logsift.pl --format cef   auth.log   # ArcSight CEF, for SIEM ingest
```

Pipe CEF straight to a syslog collector:

```bash
perl logsift.pl --format cef /var/log/auth.log | logger -n siem.internal -P 514 -t logsift
```

## Tuning detectors

Defaults are conservative. Tighten or loosen per environment:

```bash
# a noisy edge host: only alert on heavier bursts
perl logsift.pl --fail-threshold 25 --spray-threshold 10 auth.log

# hunt aggressive web scanners
perl logsift.pl --format-in nginx --scan-paths 8 --error-burst 40 access.log

# 5-minute rate buckets, 2-sigma spike sensitivity
perl logsift.pl --bucket 300 --spike-sigma 2 app.log

# report any log signature seen 5 times or fewer
perl logsift.pl --rare-max 5 app.log
```

## Allowlisting

Suppress findings for known-good sources (scanners, jump hosts, health checkers):

```bash
perl logsift.pl --allowlist-ip 10.0.0.5 --allowlist-ip 10.0.0.6 auth.log
```

An allowlisted IP is excluded from brute/spray/http detectors but still counted in the
event totals and signature/rate baselines.

## Exit codes in a pipeline

```bash
if perl logsift.pl --format cef "$LOG" > findings.cef; then
    echo "clean"           # exit 0
else
    case $? in
      2) forward_to_siem findings.cef ;;   # findings present
      1) echo "logsift error" >&2 ;;       # bad input/option
    esac
fi
```
