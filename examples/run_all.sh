#!/bin/sh
# Run every demo. Exits 0 only if all demos succeed.
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# ensure generated samples exist
perl "$DIR/logs/gen_nginx.pl" > "$DIR/logs/nginx-access.log"
perl "$DIR/logs/gen_spike.pl" > "$DIR/logs/spike.log"
for d in 01_ssh_brute_force 02_password_spray 03_web_scan 04_rate_spike 05_cef_for_siem; do
    echo "======================================================================"
    echo "DEMO: $d"
    echo "======================================================================"
    sh "$DIR/$d.sh"
done
echo "======================================================================"
echo "ALL DEMOS PASSED"
