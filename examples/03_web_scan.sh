#!/bin/sh
# Detect web path-scanning in an nginx combined access log
# (one IP hitting many distinct paths + a 4xx burst).
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LS="perl $DIR/../logsift.pl"
$LS --format-in nginx --format text "$DIR/logs/nginx-access.log"
if $LS --format-in nginx --format json "$DIR/logs/nginx-access.log" | grep -q '"http_scan"'; then
  echo "OK: http_scan detected"; exit 0
fi
echo "FAIL: expected http_scan"; exit 1
