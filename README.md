# logsift

**Perl** — Auth-log brute-force & password-spray detector for SSH/PAM logs.

[![ci](https://github.com/cognis-digital/logsift-perl/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/logsift-perl/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-Perl-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** — 370+ single-purpose, self-hostable tools. Like every tool in the suite, `logsift` is single-purpose, emits machine-readable JSON, and exits non-zero when it finds something (CI-friendly).


<!-- cognis:example:start -->
## 🔎 Example output

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
    "log": [
        {
            "timestamp": 1643723400,
            "level": "INFO",
            "message": "Started processing request for user 'jane' and item 'book1'",
            "logger_name": "com.example.app.RequestProcessor"
        },
        {
            "timestamp": 1643723410,
            "level": "ERROR",
            "message": "Failed to retrieve data for user 'jane' and item 'book1': java.io.IOException: File not found",
            "logger_name": "com.example.app.DataRetriever"
        }
    ]
}
```

<!-- cognis:example:end -->

## Build / run

```bash
perl logsift.pl sample.log   # no build step; pure Perl 5
```

## Usage

```
perl logsift.pl /var/log/auth.log
journalctl -u ssh | perl logsift.pl -
  --fail-threshold N    failures from one IP to flag brute force (default 5)
  --spray-threshold N   distinct users from one IP to flag spray (default 5)
```

## Output

A JSON object on stdout. Exit code **2** when findings exist, **0** when clean, **1** on error — so you can gate CI/pipelines on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
