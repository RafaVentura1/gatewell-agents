#!/usr/bin/env bash
#
# mkdist-linux.sh <build_dir> <distribution.xml> <out.pkg>
#
# Wraps a component package into a macOS *distribution* package without Apple's
# productbuild, for building on Linux CI. A distribution .pkg is a xar archive
# containing:
#
#   Distribution      the installer-gui-script XML
#   <name>.pkg/       a directory holding the component's members
#                     (PackageInfo, Bom, Payload, Scripts)
#
# Requires: xar.
#
set -euo pipefail

BUILD_DIR="${1:?build dir}"
DIST_XML="${2:?distribution.xml}"
OUT="${3:?output pkg}"

command -v xar >/dev/null 2>&1 || {
  echo "mkdist-linux.sh: xar not found" >&2
  exit 1
}

COMPONENT="${BUILD_DIR}/component.pkg"
[[ -f "$COMPONENT" ]] || {
  echo "mkdist-linux.sh: ${COMPONENT} not found" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FLAT="${WORK}/flat"
mkdir -p "${FLAT}/component.pkg"

# Unpack the component archive so its members sit inside a directory entry,
# which is how a distribution package embeds a component.
( cd "${FLAT}/component.pkg" && xar -xf "$COMPONENT" )

cp "$DIST_XML" "${FLAT}/Distribution"

# Distribution must be the first member in the archive.
( cd "$FLAT" && xar --compression none -cf "${WORK}/out.pkg" Distribution component.pkg )

mkdir -p "$(dirname "$OUT")"
mv "${WORK}/out.pkg" "$OUT"
echo "    distribution package assembled: $(basename "$OUT")"
