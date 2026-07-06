#!/bin/sh
# Detect an SSH brute-force burst (many failures from one IP).
# Expect a brute_force finding tagged ATT&CK T1110.001.
# NOTE: logsift exits 2 when it finds something (by design), so we don't
# use `set -e` around it; we assert on its output instead.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LS="perl $DIR/../logsift.pl"
$LS --format text "$DIR/logs/auth.log"
echo "--- (json, grep for T1110.001) ---"
if $LS --format json "$DIR/logs/auth.log" | grep -q 'T1110.001'; then
  echo "OK: brute_force tagged T1110.001"
  exit 0
fi
echo "FAIL: expected T1110.001"; exit 1
