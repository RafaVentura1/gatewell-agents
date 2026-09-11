# Gatewell Endpoint Agents

Cross-platform fleet security agent for the Gatewell zero-trust platform, plus
the GitHub Actions CI that packages per-organization installers.

The agent does five things on every endpoint:

1. **Enrolls** once, receiving a long-lived API token it stores securely
2. **Heartbeats** every 60s so the platform knows the device is alive and in policy
3. **Polls for commands** every 30s and executes dispatched remediation scripts
4. **Reports security events** in batches
5. **Collects EDR telemetry** — process, registry, and network activity

The full wire contract lives in [`docs/API.md`](docs/API.md).

---

## Layout

```
gatewell-agents/
├── windows/GatewellAgent/         .NET 8 Windows Service (C#, BCL only)
│   ├── ServiceHost.cs             SCM integration via advapi32 P/Invoke
│   ├── Native.cs                  DPAPI, registry and event log interop
│   └── AgentLog.cs                rotating file + event log
├── macos/gatewell-agent-mac/      Go agent — shared macOS + Linux source
│   ├── build-pkg.sh               → GatewellAgent-<org>-macos.pkg
│   ├── mkpkg-linux.sh             pkgbuild replacement for Linux builds
│   ├── mkdist-linux.sh            productbuild replacement for Linux builds
│   ├── mklipo-linux.py            lipo replacement (universal Mach-O)
│   ├── com.gatewell.agent.plist   launchd daemon definition
│   ├── collector_darwin.go        macOS telemetry (build-tagged)
│   └── collector_linux.go         Linux telemetry (build-tagged)
├── build-deb.sh                   → GatewellAgent-<org>-amd64.deb
├── build-rpm.sh                   → GatewellAgent-<org>-amd64.rpm
├── .github/workflows/             CI — one workflow per platform
└── docs/API.md                    exact request/response payloads
```

**One Go source tree serves macOS and Linux.** The platform-specific telemetry
collectors are separated by build tags (`//go:build darwin` / `//go:build
linux`), so `GOOS` selects the right implementation at compile time. The Linux
build scripts sit at the repo root per the layout contract and cross-compile
from `macos/gatewell-agent-mac/`.

---

## Build-time stamping

Each installer is built for one organization. `ORG_ID` is baked into the binary
so the agent knows which tenant to enroll against — there is no runtime config
file to distribute.

| Platform | Mechanism |
|---|---|
| Windows | CI string-replaces `__ORG_ID__` in `windows/GatewellAgent/Config.cs` before `dotnet publish` |
| macOS / Linux | `go build -ldflags "-X main.OrgID=<id>"` |

`ENROLLMENT_TOKEN` is stamped the same way when a per-org enrollment token is in
use. Both placeholders start with `__`, and the agent logs a warning at startup
if it detects an unstamped build — an unstamped agent will be rejected at
enrollment rather than silently joining the wrong org.

---

## Building locally

### Windows

```powershell
# from repo root
(Get-Content windows/GatewellAgent/Config.cs -Raw) `
  -replace '__ORG_ID__','org_abc123' |
  Set-Content windows/GatewellAgent/Config.cs -NoNewline

dotnet publish windows/GatewellAgent/GatewellAgent.csproj `
  -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true -o publish
```

`dotnet build` alone needs no network access at all, because the project has
zero `PackageReference` entries. A source is only required for the
self-contained publish, which downloads the win-x64 runtime pack.

Run in the foreground for local testing without installing the service:

```powershell
GatewellAgent.exe --console
```

Install the service (elevated):

```powershell
sc.exe create GatewellAgent binPath= "C:\Program Files\Gatewell\GatewellAgent.exe" start= auto obj= LocalSystem
sc.exe description GatewellAgent "Gatewell endpoint security agent"
sc.exe failure GatewellAgent reset= 86400 actions= restart/30000/restart/60000/restart/120000
sc.exe start GatewellAgent
```

### macOS

```bash
cd macos/gatewell-agent-mac
./build-pkg.sh org_abc123
sudo installer -pkg GatewellAgent-org_abc123-macos.pkg -target /
```

Signing and notarization are optional and gated on environment variables
(`DEVELOPER_ID_APP`, `DEVELOPER_ID_INSTALLER`, `APPLE_ID`, `APPLE_TEAM_ID`,
`APPLE_APP_PASSWORD`). With none set, the script produces an unsigned `.pkg` and
still exits successfully.

**Building the `.pkg` on Linux.** `build-pkg.sh` uses Apple's `pkgbuild`,
`productbuild` and `lipo` when they exist. On a machine without them it falls
back to assembling the flat package directly — `mkpkg-linux.sh` builds the
component archive with `xar`, `mkbom` and `cpio`, `mkdist-linux.sh` wraps it as
a distribution package, and `mklipo-linux.py` writes the universal Mach-O
container. The result is byte-compatible with a `productbuild` package. Requires
`xar`, `bomutils` and `cpio`; both `xar` and `bomutils` build from source.

### Linux

```bash
./build-deb.sh org_abc123     # Debian / Ubuntu
./build-rpm.sh org_abc123     # RHEL / Fedora / Rocky

sudo dpkg -i GatewellAgent-org_abc123-amd64.deb
# or
sudo rpm -i  GatewellAgent-org_abc123-amd64.rpm
```

Requires Go 1.21+, and `dpkg-dev` or `rpm` respectively.

---

## CI contract

The Gatewell platform dispatches these workflows remotely and polls the run to
decide whether an installer is Ready or Failed. **The file names, the input
name, and the artifact names below are a hard contract — changing any of them
breaks the platform's installer pipeline.**

| Workflow | Runner | Input | Artifact(s) |
|---|---|---|---|
| `build-windows.yml` | `windows-latest` | `org_id` | `GatewellAgent-{org_id}-windows-x64.exe` |
| `build-macos.yml` | `macos-latest` | `org_id` | `GatewellAgent-{org_id}-macos.pkg` |
| `build-linux.yml` | `ubuntu-latest` | `org_id` | `GatewellAgent-{org_id}-amd64.deb` **and** `GatewellAgent-{org_id}-amd64.rpm` |

All three trigger on `workflow_dispatch` with exactly one input, are dispatched
against `main`, use `actions/upload-artifact@v4`, and must exit successfully on
a clean build. No signing secrets are required — builds succeed without them.

---

## Local state on the endpoint

| | Windows | macOS | Linux |
|---|---|---|---|
| device_id | `HKLM\SOFTWARE\Gatewell\Agent` + `%ProgramData%\Gatewell\device_id` | `/etc/gatewell/device_id` | `/etc/gatewell/device_id` |
| API token | `%ProgramData%\Gatewell\api_token.dat` (DPAPI) | `/Library/Application Support/Gatewell/api_token` | `/etc/gatewell/api_token` |
| policy version | `%ProgramData%\Gatewell\policy_version` | `/etc/gatewell/policy_version` | `/etc/gatewell/policy_version` |
| logs | Event Log + `%ProgramData%\Gatewell\logs\agent.log` (rotating) | `/var/log/gatewell-agent.log` | `journalctl -u gatewell-agent` |

All state files are 0600 root / SYSTEM+Administrators only. The device_id is
written to two locations on Windows so an agent reinstall that clears one still
recovers the same identity.

---

## Uninstall

**Windows**

```powershell
sc.exe stop GatewellAgent
sc.exe delete GatewellAgent
Remove-Item -Recurse -Force "$env:ProgramData\Gatewell"
Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Gatewell"
```

**macOS**

```bash
sudo launchctl bootout system/com.gatewell.agent
sudo rm /Library/LaunchDaemons/com.gatewell.agent.plist
sudo rm /usr/local/bin/gatewell-agent
sudo rm -rf /etc/gatewell "/Library/Application Support/Gatewell"
```

**Linux**

```bash
sudo dpkg -r gatewell-agent      # or: sudo rpm -e gatewell-agent
sudo rm -rf /etc/gatewell
```

---

## Design notes

**The agent never crashes on network failure.** Every call is wrapped with
backoff and a bounded retry, `429` responses honour `retry_after_seconds`, and
each of the five runtime loops is isolated so a fault in one cannot take the
others down. An endpoint that cannot reach the platform for days keeps buffering
within a fixed memory cap and resumes cleanly.

**Nothing secret is ever logged.** The API token, enrollment token, and ORG_ID
are excluded from every log path by construction.

**Telemetry is sampled, not event-driven.** This is a background service on
end-user machines, so the collector takes a snapshot every 15s and diffs it
rather than hooking every syscall. ETW, EndpointSecurity, and eBPF are the
phase-2 upgrade.

**Zero third-party dependencies, literally.** The Go agent is stdlib-only and
the Windows project has no `PackageReference` entries at all. Three things that
would normally require NuGet are done through P/Invoke instead:

| Would need | Replaced by |
|---|---|
| `Microsoft.Extensions.Hosting.WindowsServices` | `ServiceHost.cs` — `StartServiceCtrlDispatcher`, `RegisterServiceCtrlHandlerEx`, `SetServiceStatus` |
| `System.Security.Cryptography.ProtectedData` | `Native.cs` — `CryptProtectData` / `CryptUnprotectData` |
| `System.Diagnostics.EventLog` | `Native.cs` — `RegisterEventSource` / `ReportEvent` |

The agent targets `net8.0` rather than `net8.0-windows` for the same reason:
the Windows-specific target framework pulls a reference pack from NuGet.
`AssemblyInfo.cs` marks the assembly `[SupportedOSPlatform("windows")]` so the
platform-compatibility analyzer still validates every Windows-only call.
