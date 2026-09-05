#!/bin/sh
# Compiles lab reports. Run with no arguments to build every lab, or pass
# lab names: ./build.sh lab1 lab3
#
# --root is set to the lab directory so report/main.typ can pull the actual
# sources into listings via read("../src/...").

set -eu

cd "$(dirname "$0")"

labs=${*:-$(ls -d lab*/ 2>/dev/null | tr -d /)}

for lab in $labs; do
  [ -f "$lab/report/main.typ" ] || { echo "skip $lab (no report/main.typ)"; continue; }
  echo "building $lab"
  typst compile --root "$lab" "$lab/report/main.typ" "$lab/report/$lab.pdf"
done
