#!/usr/bin/env bash
#
# build-pkg.sh <org_id>
#
# Builds a universal (arm64 + amd64) gatewell-agent binary with ORG_ID stamped
# in, then productbuild a distribution .pkg that installs:
#
#   /usr/local/bin/gatewell-agent
#   /Library/LaunchDaemons/com.gatewell.agent.plist
#
# and starts the daemon via postinstall.
#
# Output: GatewellAgent-<org_id>-macos.pkg  (CI artifact name contract)
#
# Signing and notarization are OPTIONAL and gated on environment variables, so
# this script succeeds on a runner with no credentials. Set these to enable:
#
#   DEVELOPER_ID_APP        "Developer ID Application: Name (TEAMID)"
#   DEVELOPER_ID_INSTALLER  "Developer ID Installer: Name (TEAMID)"
#   APPLE_ID                Apple ID email for notarytool
#   APPLE_TEAM_ID           10-char team id
#   APPLE_APP_PASSWORD      app-specific password
#
set -euo pipefail

ORG_ID="${1:-}"
if [[ -z "$ORG_ID" ]]; then
  echo "usage: $0 <org_id>" >&2
  exit 2
fi

VERSION="1.0.0"
IDENTIFIER="io.gatewell.agent"
BINARY="gatewell-agent"
PKG_NAME="GatewellAgent-${ORG_ID}-macos.pkg"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
ROOT_DIR="${BUILD_DIR}/root"
SCRIPTS_DIR="${BUILD_DIR}/scripts"

echo "==> Building Gatewell macOS agent"
echo "    org_id  : ${ORG_ID}"
echo "    version : ${VERSION}"

rm -rf "$BUILD_DIR"
mkdir -p "${ROOT_DIR}/usr/local/bin"
mkdir -p "${ROOT_DIR}/Library/LaunchDaemons"
mkdir -p "$SCRIPTS_DIR"

# ---- 1. compile universal binary -------------------------------------------
echo "==> Compiling (arm64 + amd64)"
cd "$SCRIPT_DIR"

LDFLAGS="-s -w -X main.OrgID=${ORG_ID}"
if [[ -n "${ENROLLMENT_TOKEN:-}" ]]; then
  LDFLAGS="${LDFLAGS} -X main.EnrollmentToken=${ENROLLMENT_TOKEN}"
fi

CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
  go build -ldflags "$LDFLAGS" -o "${BUILD_DIR}/${BINARY}-amd64" .
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -ldflags "$LDFLAGS" -o "${BUILD_DIR}/${BINARY}-arm64" .

if command -v lipo >/dev/null 2>&1; then
  lipo -create -output "${ROOT_DIR}/usr/local/bin/${BINARY}" \
    "${BUILD_DIR}/${BINARY}-amd64" "${BUILD_DIR}/${BINARY}-arm64"
else
  # lipo is macOS-only; write the fat container directly so Linux builds are
  # still universal rather than silently degrading to a single architecture.
  echo "    lipo unavailable - writing universal binary directly"
  python3 "${SCRIPT_DIR}/mklipo-linux.py" \
    "${ROOT_DIR}/usr/local/bin/${BINARY}" \
    "${BUILD_DIR}/${BINARY}-amd64" "${BUILD_DIR}/${BINARY}-arm64"
fi
chmod 755 "${ROOT_DIR}/usr/local/bin/${BINARY}"

cp "${SCRIPT_DIR}/com.gatewell.agent.plist" \
   "${ROOT_DIR}/Library/LaunchDaemons/com.gatewell.agent.plist"
chmod 644 "${ROOT_DIR}/Library/LaunchDaemons/com.gatewell.agent.plist"

# ---- 2. OPTIONAL: codesign the binary ---------------------------------------
if [[ -n "${DEVELOPER_ID_APP:-}" ]]; then
  echo "==> Code signing binary"
  codesign --force --options runtime --timestamp \
    --sign "${DEVELOPER_ID_APP}" \
    "${ROOT_DIR}/usr/local/bin/${BINARY}"
else
  echo "==> Skipping code signing (DEVELOPER_ID_APP unset)"
fi

# ---- 3. install scripts -----------------------------------------------------
cat > "${SCRIPTS_DIR}/preinstall" <<'PREINSTALL'
#!/bin/bash
# Stop any previously installed agent so the binary can be replaced cleanly.
/bin/launchctl bootout system/com.gatewell.agent 2>/dev/null || true
/bin/launchctl unload /Library/LaunchDaemons/com.gatewell.agent.plist 2>/dev/null || true
exit 0
PREINSTALL

cat > "${SCRIPTS_DIR}/postinstall" <<'POSTINSTALL'
#!/bin/bash
set -e
mkdir -p /etc/gatewell
chmod 700 /etc/gatewell
mkdir -p "/Library/Application Support/Gatewell"
chmod 700 "/Library/Application Support/Gatewell"

chown root:wheel /Library/LaunchDaemons/com.gatewell.agent.plist
chmod 644 /Library/LaunchDaemons/com.gatewell.agent.plist
chown root:wheel /usr/local/bin/gatewell-agent
chmod 755 /usr/local/bin/gatewell-agent

# bootstrap is the modern form; fall back to load on older systems.
/bin/launchctl bootstrap system /Library/LaunchDaemons/com.gatewell.agent.plist 2>/dev/null \
  || /bin/launchctl load -w /Library/LaunchDaemons/com.gatewell.agent.plist

echo "Gatewell agent installed and started."
exit 0
POSTINSTALL

chmod 755 "${SCRIPTS_DIR}/preinstall" "${SCRIPTS_DIR}/postinstall"

# ---- 4. component + distribution package ------------------------------------
# pkgbuild/productbuild are macOS-only. When they are absent (Linux CI or a
# developer box) fall back to assembling the .pkg from its parts with xar,
# mkbom and cpio, which produces a byte-compatible flat package.
if command -v pkgbuild >/dev/null 2>&1; then
  echo "==> pkgbuild"
  pkgbuild \
    --root "$ROOT_DIR" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --install-location "/" \
    "${BUILD_DIR}/component.pkg"
else
  echo "==> pkgbuild unavailable - assembling component.pkg with xar/mkbom"
  "${SCRIPT_DIR}/mkpkg-linux.sh" \
      "$ROOT_DIR" "$SCRIPTS_DIR" "$IDENTIFIER" "$VERSION" \
      "${BUILD_DIR}/component.pkg"
fi

cat > "${BUILD_DIR}/distribution.xml" <<DISTXML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Gatewell Agent</title>
  <options customize="never" require-scripts="true" hostArchitectures="x86_64,arm64"/>
  <domains enable_localSystem="true"/>
  <pkg-ref id="${IDENTIFIER}"/>
  <choices-outline>
    <line choice="default"/>
  </choices-outline>
  <choice id="default" title="Gatewell Agent">
    <pkg-ref id="${IDENTIFIER}"/>
  </choice>
  <pkg-ref id="${IDENTIFIER}" version="${VERSION}" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
DISTXML

if command -v productbuild >/dev/null 2>&1; then
  echo "==> productbuild"
  if [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then
    productbuild \
      --distribution "${BUILD_DIR}/distribution.xml" \
      --package-path "$BUILD_DIR" \
      --sign "${DEVELOPER_ID_INSTALLER}" \
      "${SCRIPT_DIR}/${PKG_NAME}"
  else
    echo "    (unsigned)"
    productbuild \
      --distribution "${BUILD_DIR}/distribution.xml" \
      --package-path "$BUILD_DIR" \
      "${SCRIPT_DIR}/${PKG_NAME}"
  fi
else
  echo "==> productbuild unavailable - assembling distribution pkg with xar"
  "${SCRIPT_DIR}/mkdist-linux.sh" \
      "$BUILD_DIR" "${BUILD_DIR}/distribution.xml" "${SCRIPT_DIR}/${PKG_NAME}"
fi

# ---- 5. OPTIONAL: notarize --------------------------------------------------
if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  echo "==> Notarizing"
  xcrun notarytool submit "${SCRIPT_DIR}/${PKG_NAME}" \
    --apple-id "${APPLE_ID}" \
    --team-id "${APPLE_TEAM_ID}" \
    --password "${APPLE_APP_PASSWORD}" \
    --wait
  xcrun stapler staple "${SCRIPT_DIR}/${PKG_NAME}"
else
  echo "==> Skipping notarization (Apple credentials unset)"
fi

echo ""
echo "Built: ${SCRIPT_DIR}/${PKG_NAME}"
echo "Install with: sudo installer -pkg ${PKG_NAME} -target /"
