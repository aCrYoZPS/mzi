#!/bin/sh
# Installs the BSUIR STP 01-2024 typst template as a local typst package.
# Run once per machine; afterwards every report just does:
#     #import "@local/stp2024:0.1.0"
# No symlinks, no per-OS setup in the repo itself.

set -eu

NAME=stp2024
VERSION=0.1.0
SRC_REPO=git@github.com-personal:aCrYoZPS/typst.git
SRC_DIR=${TYPST_TEMPLATE_SRC:-$HOME/typst}

# Where typst looks for @local packages, per platform.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) DATA_DIR=${APPDATA:?APPDATA is not set} ;;
  Darwin)               DATA_DIR="$HOME/Library/Application Support" ;;
  *)                    DATA_DIR=${XDG_DATA_HOME:-$HOME/.local/share} ;;
esac
DEST="$DATA_DIR/typst/packages/local/$NAME/$VERSION"

if [ ! -d "$SRC_DIR/lib" ]; then
  echo "Template sources not found at $SRC_DIR, cloning..."
  git clone "$SRC_REPO" "$SRC_DIR"
fi

echo "Installing $NAME:$VERSION -> $DEST"
rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SRC_DIR"/lib/*.typ "$SRC_DIR"/lib/*.csl "$DEST/"

cat > "$DEST/typst.toml" <<EOF
[package]
name = "$NAME"
version = "$VERSION"
entrypoint = "stp2024.typ"
authors = ["aCrYoZPS"]
license = "MIT"
description = "BSUIR STP 01-2024 report template"
EOF

echo "Done. Reports can now use: #import \"@local/$NAME:$VERSION\""
echo
echo "Note: the template expects the fonts Times New Roman, Courier New and"
echo "GOST type B ($SRC_DIR/fonts) to be installed system-wide."
