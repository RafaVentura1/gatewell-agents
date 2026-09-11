#!/usr/bin/env bash
#
# build-rpm.sh <org_id>
#
# Cross-compiles the shared Go agent for linux/amd64 with ORG_ID stamped in and
# builds an RPM installing:
#
#   /usr/local/bin/gatewell-agent
#   /usr/lib/systemd/system/gatewell-agent.service
#
# Output: GatewellAgent-<org_id>-amd64.rpm   (CI artifact name contract)
#
set -euo pipefail

ORG_ID="${1:-}"
if [[ -z "$ORG_ID" ]]; then
  echo "usage: $0 <org_id>" >&2
  exit 2
fi

VERSION="1.0.0"
RELEASE="1"
BINARY="gatewell-agent"
RPM_NAME="GatewellAgent-${ORG_ID}-amd64.rpm"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${REPO_DIR}/macos/gatewell-agent-mac"   # shared Go agent source
TOP_DIR="${REPO_DIR}/dist/rpmbuild"

echo "==> Building Gatewell Linux agent (.rpm)"
echo "    org_id  : ${ORG_ID}"
echo "    version : ${VERSION}"

rm -rf "$TOP_DIR"
mkdir -p "${TOP_DIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# ---- compile ---------------------------------------------------------------
LDFLAGS="-s -w -X main.OrgID=${ORG_ID}"
if [[ -n "${ENROLLMENT_TOKEN:-}" ]]; then
  LDFLAGS="${LDFLAGS} -X main.EnrollmentToken=${ENROLLMENT_TOKEN}"
fi

echo "==> Compiling linux/amd64"
( cd "$SRC_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "$LDFLAGS" -o "${TOP_DIR}/SOURCES/${BINARY}" . )
chmod 755 "${TOP_DIR}/SOURCES/${BINARY}"

# ---- systemd unit -----------------------------------------------------------
cat > "${TOP_DIR}/SOURCES/gatewell-agent.service" <<'UNIT'
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

# ---- spec -------------------------------------------------------------------
cat > "${TOP_DIR}/SPECS/gatewell-agent.spec" <<SPEC
# Go produces a stripped static binary with no GNU build-id and nothing to
# extract debuginfo from. Without these, rpmbuild on RHEL/Fedora fails the
# build with "Missing build-id" or an empty debuginfo package.
%global debug_package %{nil}
%global __os_install_post %{nil}
%undefine _missing_build_ids_terminate_build

Name:           gatewell-agent
Version:        ${VERSION}
Release:        ${RELEASE}
Summary:        Gatewell endpoint security agent
License:        Proprietary
URL:            https://gatewell.io
BuildArch:      x86_64
Requires:       systemd
AutoReqProv:    no

%description
Cross-platform fleet agent for the Gatewell zero-trust platform.
Reports device heartbeat, executes dispatched remediation scripts,
and forwards security events and EDR telemetry to the platform.

%install
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/etc/gatewell
install -m 755 %{_sourcedir}/gatewell-agent \\
        %{buildroot}/usr/local/bin/gatewell-agent
install -m 644 %{_sourcedir}/gatewell-agent.service \\
        %{buildroot}/usr/lib/systemd/system/gatewell-agent.service

%files
%attr(0755, root, root) /usr/local/bin/gatewell-agent
%attr(0644, root, root) /usr/lib/systemd/system/gatewell-agent.service
%dir %attr(0700, root, root) /etc/gatewell

%post
systemctl daemon-reload
systemctl enable gatewell-agent >/dev/null 2>&1 || true
systemctl restart gatewell-agent || systemctl start gatewell-agent
echo "Gatewell agent installed and started."

%preun
if [ \$1 -eq 0 ]; then
    systemctl stop gatewell-agent 2>/dev/null || true
    systemctl disable gatewell-agent 2>/dev/null || true
fi

%postun
systemctl daemon-reload 2>/dev/null || true

%clean
rm -rf %{buildroot}
SPEC

# ---- build ------------------------------------------------------------------
echo "==> rpmbuild"
rpmbuild --define "_topdir ${TOP_DIR}" \
         -bb "${TOP_DIR}/SPECS/gatewell-agent.spec" >/dev/null

BUILT="$(find "${TOP_DIR}/RPMS" -name '*.rpm' -print -quit)"
if [[ -z "$BUILT" ]]; then
  echo "rpmbuild produced no output" >&2
  exit 1
fi
cp "$BUILT" "${REPO_DIR}/${RPM_NAME}"

echo ""
echo "Built: ${REPO_DIR}/${RPM_NAME}"
echo "Install with: sudo rpm -i ${RPM_NAME}"
