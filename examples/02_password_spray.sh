#!/bin/sh
# Detect a password spray (one IP against many distinct users).
# Expect a password_spray finding tagged ATT&CK T1110.003.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LS="perl $DIR/../logsift.pl"
$LS --format text "$DIR/logs/spray.log"
if $LS --format json "$DIR/logs/spray.log" | grep -q 'T1110.003'; then
  echo "OK: password_spray tagged T1110.003"; exit 0
fi
echo "FAIL: expected T1110.003"; exit 1
