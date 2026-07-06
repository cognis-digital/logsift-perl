#!/bin/sh
# Emit ArcSight CEF for findings, ready to ship to a SIEM.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LS="perl $DIR/../logsift.pl"
echo "--- CEF (auth.log) ---"
$LS --format cef "$DIR/logs/auth.log"
echo "--- NDJSON (stream to a collector) ---"
$LS --format ndjson "$DIR/logs/auth.log"
if $LS --format cef "$DIR/logs/auth.log" | grep -qE '^CEF:0\|Cognis\|logsift\|'; then
  echo "OK: well-formed CEF header"; exit 0
fi
echo "FAIL: malformed CEF"; exit 1
