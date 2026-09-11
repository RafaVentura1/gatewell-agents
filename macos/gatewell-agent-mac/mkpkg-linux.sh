#!/usr/bin/env bash
#
# mkpkg-linux.sh <payload_root> <scripts_dir> <identifier> <version> <out.pkg>
#
# Assembles a macOS *component* package without Apple's pkgbuild, for building
# on Linux CI. A component .pkg is a xar archive containing:
#
#   PackageInfo   XML describing the payload, install location and scripts
#   Payload       gzip-compressed cpio (odc format) of the file tree
#   Scripts       gzip-compressed cpio of pre/postinstall, omitted if empty
#   Bom           binary bill of materials, produced by mkbom
#
# Requires: xar, mkbom (bomutils), cpio, gzip.
#
set -euo pipefail

PAYLOAD_ROOT="${1:?payload root}"
SCRIPTS_DIR="${2:?scripts dir}"
IDENTIFIER="${3:?identifier}"
VERSION="${4:?version}"
OUT="${5:?output pkg}"

for tool in xar mkbom cpio gzip; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "mkpkg-linux.sh: required tool '$tool' not found" >&2
    exit 1
  }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FLAT="${WORK}/flat"
mkdir -p "$FLAT"

# ---- Payload: gzip'd cpio of the payload tree -------------------------------
# odc is the portable ASCII format Installer expects. Paths are stored relative
# to the payload root with a leading "." so they resolve against the install
# location.
( cd "$PAYLOAD_ROOT" && find . -print | sort | cpio -o --format=odc --quiet ) \
  | gzip -9 -n > "${FLAT}/Payload"

# ---- Bom: bill of materials over the same tree ------------------------------
mkbom -u 0 -g 80 "$PAYLOAD_ROOT" "${FLAT}/Bom"

# ---- Scripts: gzip'd cpio, only when scripts exist --------------------------
HAS_SCRIPTS=0
if [[ -d "$SCRIPTS_DIR" ]] && [[ -n "$(ls -A "$SCRIPTS_DIR" 2>/dev/null)" ]]; then
  HAS_SCRIPTS=1
  ( cd "$SCRIPTS_DIR" && find . -print | sort | cpio -o --format=odc --quiet ) \
    | gzip -9 -n > "${FLAT}/Scripts"
fi

# ---- PackageInfo ------------------------------------------------------------
# numberOfFiles and installKBytes are advisory; Installer recomputes from the
# Bom, but populating them keeps the metadata honest.
NUM_FILES="$(find "$PAYLOAD_ROOT" | wc -l | tr -d ' ')"
INSTALL_KB="$(du -sk "$PAYLOAD_ROOT" | cut -f1)"

{
  echo '<?xml version="1.0" encoding="utf-8"?>'
  printf '<pkg-info format-version="2" identifier="%s" version="%s" ' \
         "$IDENTIFIER" "$VERSION"
  printf 'install-location="/" auth="root" relocatable="false" overwrite-permissions="true">\n'
  printf '    <payload installKBytes="%s" numberOfFiles="%s"/>\n' \
         "$INSTALL_KB" "$NUM_FILES"
  if [[ $HAS_SCRIPTS -eq 1 ]]; then
    echo '    <scripts>'
    [[ -f "${SCRIPTS_DIR}/preinstall"  ]] && echo '        <preinstall file="./preinstall"/>'
    [[ -f "${SCRIPTS_DIR}/postinstall" ]] && echo '        <postinstall file="./postinstall"/>'
    echo '    </scripts>'
  fi
  echo '</pkg-info>'
} > "${FLAT}/PackageInfo"

# ---- Wrap as a xar archive --------------------------------------------------
# Order matters: Installer expects PackageInfo first. --compression none keeps
# the already-compressed members intact.
( cd "$FLAT" && xar --compression none -cf "${WORK}/component.pkg" \
    PackageInfo Bom Payload $( [[ $HAS_SCRIPTS -eq 1 ]] && echo Scripts ) )

mkdir -p "$(dirname "$OUT")"
mv "${WORK}/component.pkg" "$OUT"
echo "    component package assembled: $(basename "$OUT")"
