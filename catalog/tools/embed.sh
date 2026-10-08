#!/bin/sh
# embed.sh <file> <out.inc>: turns a text file into adjacent C string literals (one per
# line) so cxpy.c can #include its bootstrap. POSIX sh + sed only.
set -eu
[ $# -eq 2 ] || { echo "usage: embed.sh <file> <out.inc>" >&2; exit 2; }
sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$/\\n"/' "$1" > "$2.tmp"
mv "$2.tmp" "$2"
