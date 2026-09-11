#!/usr/bin/env bash
#
# build-deb.sh <org_id>
#
# Cross-compiles the shared Go agent for linux/amd64 with ORG_ID stamped in and
# assembles a Debian package installing:
#
#   /usr/local/bin/gatewell-agent
#   /lib/systemd/system/gatewell-agent.service
#
# postinst enables and starts the service.
#
# Output: GatewellAgent-<org_id>-amd64.deb   (CI artifact name contract)
#
set -euo pipefail

ORG_ID="${1:-}"
if [[ -z "$ORG_ID" ]]; then
  echo "usage: $0 <org_id>" >&2
  exit 2
fi

VERSION="1.0.0"
BINARY="gatewell-agent"
DEB_NAME="GatewellAgent-${ORG_ID}-amd64.deb"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${REPO_DIR}/macos/gatewell-agent-mac"   # shared Go agent source
BUILD_DIR="${REPO_DIR}/dist/deb"
PKG_ROOT="${BUILD_DIR}/gatewell-agent_${VERSION}_amd64"

echo "==> Building Gatewell Linux agent (.deb)"
echo "    org_id  : ${ORG_ID}"
echo "    version : ${VERSION}"

rm -rf "$BUILD_DIR"
mkdir -p "${PKG_ROOT}/usr/local/bin"
mkdir -p "${PKG_ROOT}/lib/systemd/system"
mkdir -p "${PKG_ROOT}/etc/gatewell"
mkdir -p "${PKG_ROOT}/DEBIAN"

# ---- compile ---------------------------------------------------------------
LDFLAGS="-s -w -X main.OrgID=${ORG_ID}"
if [[ -n "${ENROLLMENT_TOKEN:-}" ]]; then
  LDFLAGS="${LDFLAGS} -X main.EnrollmentToken=${ENROLLMENT_TOKEN}"
fi

echo "==> Compiling linux/amd64"
( cd "$SRC_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "$LDFLAGS" -o "${PKG_ROOT}/usr/local/bin/${BINARY}" . )
chmod 755 "${PKG_ROOT}/usr/local/bin/${BINARY}"
chmod 700 "${PKG_ROOT}/etc/gatewell"

# ---- systemd unit -----------------------------------------------------------
cat > "${PKG_ROOT}/lib/systemd/system/gatewell-agent.service" <<'UNIT'
[Unit]
Description=Gatewell Endpoint Agent
Documentation=https://gatewell.io/docs/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gatewell-agent
Restart=always
RestartSec=30
KillMode=process

# Root is required for /etc/gatewell, script execution, and /proc/<pid>/fd.
User=root
Group=root

PrivateTmp=true
NoNewPrivileges=false
ProtectSystem=false

StandardOutput=journal
StandardError=journal
SyslogIdentifier=gatewell-agent

Environment=HOME=/root

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "${PKG_ROOT}/lib/systemd/system/gatewell-agent.service"

# ---- control ----------------------------------------------------------------
cat > "${PKG_ROOT}/DEBIAN/control" <<CONTROL
Package: gatewell-agent
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Gatewell <support@gatewell.io>
Depends: systemd
Description: Gatewell endpoint security agent
 Cross-platform fleet agent for the Gatewell zero-trust platform.
 Reports device heartbeat, executes dispatched remediation scripts,
 and forwards security events and EDR telemetry to the platform.
CONTROL

cat > "${PKG_ROOT}/DEBIAN/conffiles" <<'CONFFILES'
CONFFILES

cat > "${PKG_ROOT}/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e
mkdir -p /etc/gatewell
chmod 700 /etc/gatewell
systemctl daemon-reload
systemctl enable gatewell-agent >/dev/null 2>&1 || true
systemctl restart gatewell-agent || systemctl start gatewell-agent
echo "Gatewell agent installed and started."
exit 0
POSTINST

cat > "${PKG_ROOT}/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl stop gatewell-agent 2>/dev/null || true
  systemctl disable gatewell-agent 2>/dev/null || true
fi
exit 0
PRERM

cat > "${PKG_ROOT}/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e
if [ "$1" = "purge" ]; then
  rm -rf /etc/gatewell
fi
systemctl daemon-reload 2>/dev/null || true
exit 0
POSTRM

chmod 755 "${PKG_ROOT}/DEBIAN/postinst" \
          "${PKG_ROOT}/DEBIAN/prerm" \
          "${PKG_ROOT}/DEBIAN/postrm"

# ---- build ------------------------------------------------------------------
echo "==> dpkg-deb"
dpkg-deb --build --root-owner-group "$PKG_ROOT" >/dev/null
mv "${PKG_ROOT}.deb" "${REPO_DIR}/${DEB_NAME}"

echo ""
echo "Built: ${REPO_DIR}/${DEB_NAME}"
echo "Install with: sudo dpkg -i ${DEB_NAME}"
