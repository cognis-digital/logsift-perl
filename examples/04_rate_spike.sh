#!/bin/sh
# Detect a rate spike: a 60s window whose event count blows past mean+3*stddev.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LS="perl $DIR/../logsift.pl"
perl "$DIR/logs/gen_spike.pl" > "$DIR/logs/spike.log"
$LS --bucket 60 --spike-sigma 3 --format text "$DIR/logs/spike.log"
if $LS --bucket 60 --format json "$DIR/logs/spike.log" | grep -q '"rate_spike"'; then
  echo "OK: rate_spike detected"; exit 0
fi
echo "FAIL: expected rate_spike"; exit 1
