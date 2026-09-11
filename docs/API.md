# Gatewell Agent ↔ Platform API

Exact wire contract between the endpoint agent and the Gatewell platform.
Keep this file in sync with any change to `api.go` / `ApiClient.cs`.

**Base URL**

```
https://gatewell-329446a6.base44.app/functions/<functionName>
```

Stamped into the agent at build time (`Config.ApiBase` on Windows, `APIBase`
in `config.go` for Go).

**Authentication**

All calls after enrollment send:

```
Authorization: Bearer agt_<token>
```

A body field `_auth_token` is accepted as a fallback where setting headers is
awkward. The token is issued by the first `agentCheckin` and must be persisted:

| Platform | Token location |
|---|---|
| Windows | `%ProgramData%\Gatewell\api_token.dat`, DPAPI `LocalMachine` scope |
| macOS | `/Library/Application Support/Gatewell/api_token`, 0600 root |
| Linux | `/etc/gatewell/api_token`, 0600 root |

The token is never written to any log.

---

## 1. `POST /functions/agentCheckin` — enrollment

First run only. No `Authorization` header; carries `enrollment_token` instead.

```json
{
  "device_id": "3f8b1c22-9d41-4e77-b0aa-6c2e1f9a4d10",
  "org_id": "org_abc123",
  "hostname": "WS-LAPTOP-01",
  "os_type": "windows",
  "os_version": "10.0.19045",
  "agent_version": "1.0.0",
  "ip_address": "192.168.1.50",
  "policy_version_current": "0",
  "enrollment_token": "<stamped at build>"
}
```

`os_type` is one of `windows` | `macos` | `linux`.
`device_id` is agent-generated on first run and persisted across restarts.

**Response**

```json
{
  "status": "ok",
  "policy_version": "12",
  "api_token": "agt_9f2c...",
  "token_issued": true
}
```

Persist `api_token` and use it for every subsequent call. If the response
contains no `api_token`, the device already has one stored — reuse it.

---

## 2. `POST /functions/agentCheckin` — heartbeat

Every **60 seconds**. Same endpoint and body as enrollment, but **with** the
Bearer token and **without** `enrollment_token`.

Always include the agent's current `policy_version_current`. If it differs from
the server's `policy_version`, the server queues a `sync_policy` command that
arrives on the next poll.

**429 handling** — the response carries `retry_after_seconds`; honour it.
A network failure must never crash the agent: back off and retry.

---

## 3. `GET /functions/agentPollCommands?device_id=<id>` — command poll

Every **30 seconds**, with the Bearer token.

**Response**

```json
[
  {
    "id": "cmd_01H...",
    "command_type": "run_script",
    "payload": { "content": "#!/bin/bash\necho hi", "script_run_id": "run_88" }
  }
]
```

### `run_script`

`payload`: `{ "content": "<script text>", "script_run_id": "<id>" }`

Write to a temp file, execute (PowerShell on Windows, bash on macOS/Linux),
capture exit code and combined stdout+stderr, then report the result. Delete the
temp file regardless of outcome.

### `sync_policy`

`payload`: `{ "policy_version": "<version>" }`

Persist it and report it as `policy_version_current` on subsequent heartbeats.
Full policy enforcement is a later phase; for now the platform only needs to see
that the agent is in sync.

### Unknown command types

Ignore gracefully and log locally. The agent emits an `unknown_command` security
event so the platform has visibility.

---

## 4. `POST /functions/agentScriptResult`

```json
{
  "script_run_id": "run_88",
  "device_id": "3f8b1c22-...",
  "exit_code": 0,
  "output_log": "<combined stdout+stderr>"
}
```

Agent-side exit code conventions for non-process failures:

| Code | Meaning |
|---|---|
| `-1` | Script exceeded the 30-minute timeout |
| `-2` | Agent-side error (could not write temp file, spawn failed) |

`output_log` is truncated to 64 KB with a `[...truncated]` marker.

---

## 5. `POST /functions/agentEvents`

**Max 100 events per batch.** Buffer locally and flush in batches.

```json
{
  "device_id": "3f8b1c22-...",
  "batch": [
    {
      "event_id": "0f4a...",
      "event_type": "policy_violation",
      "severity": "warning",
      "description": "Script run run_88 finished with exit code 1.",
      "timestamp": "2026-09-08T22:14:03Z"
    }
  ]
}
```

`severity` is one of `info` | `warning` | `medium` | `high` | `critical`.

`event_id` must be unique per event — the platform uses it to dedupe, so a
failed batch can be retried safely.

Event types the agent currently emits:

| `event_type` | When |
|---|---|
| `agent_enrolled` | Enrollment completed |
| `script_executed` | A `run_script` command finished |
| `policy_synced` | A `sync_policy` command was applied |
| `unknown_command` | An unsupported `command_type` arrived |

---

## 6. `POST /functions/agentTelemetry`

**Max 200 events per batch, and the batch must be non-empty.**

```json
{
  "device_id": "3f8b1c22-...",
  "telemetry_type": "process",
  "batch_id": "b1c9...",
  "batch": [ { "event_id": "...", "kind": "process_start", "...": "..." } ]
}
```

`telemetry_type` is one of `process` | `file` | `registry` | `network`.

**`batch_id` is an idempotency key.** Generate a fresh one per batch, but reuse
the *same* value on every retry of that batch so a retried POST is never
double-counted.

### Collected in phase 1

| OS | process | registry | network |
|---|---|---|---|
| Windows | new process starts — pid, ppid, name, path, sha256 | additions/changes under Run, RunOnce, Wow6432Node\Run, and service `ImagePath` | established TCP with owning PID via `GetExtendedTcpTable` |
| macOS | new process starts via `ps` (pid, ppid, name, path, args) | n/a | established TCP via `lsof` |
| Linux | new process starts via `/proc` (pid, ppid, comm, exe, cmdline) | n/a | `/proc/net/tcp` joined to PID through `/proc/<pid>/fd` socket inodes |

Collection is **sampled**, not event-driven: a snapshot every 15s is diffed
against the previous one, so only new activity is emitted. This keeps CPU and
memory small on end-user machines. Windows executable hashing is capped at 10
per cycle and cached by path.

Phase 2 replaces sampling with ETW (Windows), EndpointSecurity (macOS), and
eBPF or auditd (Linux).

---

## Agent timing summary

| Loop | Interval |
|---|---|
| Heartbeat | 60s |
| Command poll | 30s |
| Event flush | 60s |
| Telemetry sample | 15s |
| Telemetry flush | 120s |
| Script timeout | 30 min |
| HTTP timeout | 30s |

Retries use exponential backoff (2s → 4s → 8s, three attempts). `4xx` other than
`429` is treated as non-retryable. Buffers are capped (5,000 events, 4,000
telemetry entries) and drop oldest-first, so an agent that cannot reach the
platform for days never grows without bound.
