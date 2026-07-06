#!/bin/sh
# POSIX installer: copies logsift + its lib into a prefix and makes a launcher.
# Usage: sudo ./install.sh [PREFIX]   (default /usr/local)
set -e
PREFIX="${1:-/usr/local}"
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

LIBDIR="$PREFIX/lib/logsift"
BIN="$PREFIX/bin/logsift"

command -v perl >/dev/null 2>&1 || { echo "perl not found in PATH"; exit 1; }

echo "installing logsift lib -> $LIBDIR"
mkdir -p "$LIBDIR/lib/Logsift"
cp "$SRC/logsift.pl" "$LIBDIR/logsift.pl"
cp "$SRC/lib/Logsift/Parser.pm"    "$LIBDIR/lib/Logsift/Parser.pm"
cp "$SRC/lib/Logsift/Detectors.pm" "$LIBDIR/lib/Logsift/Detectors.pm"
cp "$SRC/lib/Logsift/Output.pm"    "$LIBDIR/lib/Logsift/Output.pm"

echo "installing launcher -> $BIN"
mkdir -p "$PREFIX/bin"
cat > "$BIN" <<EOF
#!/bin/sh
exec perl "$LIBDIR/logsift.pl" "\$@"
EOF
chmod +x "$BIN"

echo "done. try: logsift --help"
