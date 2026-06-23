# logsift

**Perl** — Auth-log brute-force & password-spray detector for SSH/PAM logs.

[![ci](https://github.com/cognis-digital/logsift/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/logsift/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-Perl-informational)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** — 370+ single-purpose, self-hostable tools. Like every tool in the suite, `logsift` is single-purpose, emits machine-readable JSON, and exits non-zero when it finds something (CI-friendly).

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
