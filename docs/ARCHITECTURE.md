# logsift architecture

```
                 +---------------------+
  raw log line   |  Logsift::Parser    |   normalized event (hashref)
  -------------> |  detect_format()    | ------------------------------+
  (streamed)     |  parse_line()       |                               |
                 +---------------------+                               v
                                                          +-------------------------+
                                                          |  Logsift::Detectors     |
                                                          |  feed(event)  (O(1)/src) |
                                                          |  finish() -> @findings   |
                                                          +-------------------------+
                                                                       |
                                                                       v
                                                          +-------------------------+
                                                          |  Logsift::Output        |
                                                          |  json|ndjson|cef|text   |
                                                          +-------------------------+
```

Everything streams: `logsift.pl` reads one line at a time, parses it to a normalized
event, feeds it to the detector engine, and never holds the whole file in memory. Per-source
state (fail counts, distinct users/paths, time buckets, signature counts) is bounded by the
number of distinct sources/signatures, not by file size.

## Normalized event schema

`Logsift::Parser::parse_line($line, $format)` returns a hashref. All keys optional except `raw`:

| key           | meaning                                            |
|---------------|----------------------------------------------------|
| `raw`         | original line (chomped)                            |
| `ts`          | epoch seconds (integer), if a timestamp parsed     |
| `ts_str`      | raw timestamp substring                            |
| `host`        | hostname                                           |
| `program`     | program / app name (`sshd`, `nginx`, …)            |
| `pid`         | process id                                         |
| `severity`    | normalized syslog severity 0..7 (lower = worse)    |
| `sev_name`    | severity name (EMERG..DEBUG)                       |
| `message`     | free-text message portion                          |
| `src_ip`      | source IPv4                                        |
| `user`        | username                                           |
| `http_status` | HTTP status code (int)                             |
| `http_path`   | request path                                       |
| `http_method` | HTTP method                                        |
| `auth_fail` / `auth_ok` | auth semantics flagged from the message  |
| `fmt`         | which parser produced the event                    |

### Severity normalization

RFC 5424 lines derive severity from the `PRI` value (`severity = PRI % 8`). Other formats map
level words (`ERROR`, `WARN`, `CRIT`, `fatal`, `trace`, …) onto the same 0..7 syslog scale.
HTTP access logs infer severity from status (`5xx → ERROR`, `4xx → WARNING`, else `INFO`).
Unknown/absent → `INFO (6)`.

## Detectors

Each detector is a streaming accumulator inside `Logsift::Detectors`; `finish()` emits findings
in a shared schema (`type, severity, src, count, window, evidence, attack?, extra`).

### Rate-spike math

Events with a timestamp are bucketed into fixed windows (`--bucket`, default 60s). At `finish()`
we compute the population mean and standard deviation of the per-bucket counts, then flag any
bucket whose count exceeds `mean + spike_sigma·stddev` (default σ=3). The finding's `evidence`
reports the baseline (`mean`, `stddev`) so the analyst can judge the signal. If `stddev == 0`
(perfectly flat rate) nothing is flagged — no divide-by-noise false positives.

### Drain-lite log templating (`rare_signature`)

Each message is reduced to a stable **signature** by replacing volatile tokens with placeholders:

| pattern                          | placeholder |
|----------------------------------|-------------|
| IPv4                             | `<IP>`      |
| MAC address                      | `<MAC>`     |
| 16+ hex chars (hashes/tokens)    | `<HASH>`    |
| ISO timestamp                    | `<TS>`      |
| `port NNN`                       | `port <NUM>`|
| any digit run                    | `<NUM>`     |

Signatures are counted. Signatures seen `≤ --rare-max` times (default 2) are reported as
`rare_signature` findings — a cheap way to surface the one weird line in a million. The top-N
most frequent signatures are also reported (as context, not findings), which doubles as a fast
"what is this log even made of" summary. This is a deliberately simple, dependency-free take on
the Drain log-parsing idea — not a statistical clustering engine.

## MITRE ATT&CK mapping (honest)

We tag findings with a technique ID **only** where the mapping is genuinely defensible.
Generic anomalies get **no** tag on purpose — over-tagging is how tools lose analyst trust.

| finding            | ATT&CK technique | rationale                                        |
|--------------------|------------------|--------------------------------------------------|
| `brute_force`      | **T1110.001**    | Brute Force: Password Guessing                   |
| `password_spray`   | **T1110.003**    | Brute Force: Password Spraying                   |
| valid-account burst| **T1078**        | Valid Accounts (successful-auth spike; reserved) |
| `http_scan`        | *(none)*         | reconnaissance signal, not a single technique    |
| `http_error_burst` | *(none)*         | too generic to map honestly                      |
| `rate_spike`       | *(none)*         | volume anomaly, not attack-specific              |
| `rare_signature`   | *(none)*         | novelty signal, not attack-specific              |

Technique IDs reference the public MITRE ATT&CK Enterprise matrix (T1110 Brute Force and its
sub-techniques; T1078 Valid Accounts).

## Output formats

- **json** — one canonical, pretty document: `tool`, `version`, `stats`, `top_signatures`, `findings[]`.
- **ndjson** — one compact JSON finding per line, for streaming into a collector.
- **cef** — `CEF:0|Cognis|logsift|VERSION|SigID|Name|Sev|extension`. Header/extension fields are
  escaped per the CEF spec (`\`, `|` in the header; `\`, `=` in extensions). ATT&CK technique rides
  in `cs1`. CEF severity (0..10) is mapped from the syslog scale.
- **text** — human summary table + severity histogram + top signatures.

## Module layout

```
logsift.pl                 CLI, arg parsing, I/O (stdin/-, files, .gz), time filters, POD
lib/Logsift/Parser.pm      format detection + per-format parsers -> normalized event
lib/Logsift/Detectors.pm   streaming detector engine + Drain-lite templating + ATT&CK table
lib/Logsift/Output.pm      json / ndjson / cef / text renderers
```
