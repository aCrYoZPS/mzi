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
  if [ -f "$lab/report/main.typ" ]; then
    echo "building $lab report"
    typst compile --root "$lab" "$lab/report/main.typ" "$lab/report/$lab.pdf"
  else
    echo "skip $lab report (no report/main.typ)"
  fi

  # Спека к защите: свободное оформление, общий стиль в docs/style.typ,
  # поэтому --root -- корень репозитория, а не каталог работы.
  if [ -f "$lab/docs/$lab-spec.typ" ]; then
    echo "building $lab spec"
    typst compile --root . "$lab/docs/$lab-spec.typ" "$lab/docs/$lab-spec.pdf"
  fi
done
