using System.Text.Json;

namespace GatewellAgent;

/// <summary>
/// The service body. Runs five independent loops so a stall in one never
/// blocks the others, and every loop treats platform unreachability as a
/// normal condition to back off from rather than an error to crash on.
/// </summary>
public sealed class AgentWorker
{
    private readonly AgentLog _log;
    private readonly DeviceIdentity _id;
    private readonly ApiClient _api;
    private readonly ScriptRunner _scripts;
    private readonly EventBuffer _events;
    private readonly TelemetryCollector _telemetry;

    private readonly HashSet<string> _handledCommands = new(StringComparer.Ordinal);

    public AgentWorker(
        AgentLog log,
        DeviceIdentity id,
        ApiClient api,
        ScriptRunner scripts,
        EventBuffer events,
        TelemetryCollector telemetry)
    {
        _log = log;
        _id = id;
        _api = api;
        _scripts = scripts;
        _events = events;
        _telemetry = telemetry;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _id.Initialize();

        if (!Config.IsStamped)
            _log.Warn("ORG_ID placeholder was not replaced at build time — " +
                "enrollment will be rejected by the platform.");

        _log.Info($"Gatewell agent {Config.AgentVersion} starting. device_id={_id.DeviceId}");

        await EnrollIfNeededAsync(ct);

        await Task.WhenAll(
            Loop("heartbeat", Config.HeartbeatIntervalSeconds, HeartbeatAsync, ct),
            Loop("poll",      Config.PollIntervalSeconds,      PollAsync,      ct),
            Loop("events",    Config.EventFlushIntervalSeconds, FlushEventsAsync, ct),
            Loop("telemetry-sample", Config.TelemetrySampleIntervalSeconds,
                 _ => { _telemetry.Sample(); return Task.CompletedTask; }, ct),
            Loop("telemetry-flush",  Config.TelemetryFlushIntervalSeconds,
                 FlushTelemetryAsync, ct));

        _log.Info("Gatewell agent stopped.");
    }

    // ---- enrollment ------------------------------------------------------

    private async Task EnrollIfNeededAsync(CancellationToken ct)
    {
        if (_id.HasToken)
        {
            _log.Info("Existing API token found, skipping enrollment.");
            return;
        }

        var delay = TimeSpan.FromSeconds(5);

        while (!ct.IsCancellationRequested && !_id.HasToken)
        {
            var result = await _api.CheckinAsync(enrolling: true, ct);

            if (result?.ApiToken is { Length: > 0 } token)
            {
                _id.StoreToken(token);
                _id.PolicyVersion = result.PolicyVersion;
                _events.Add("agent_enrolled", "info",
                    $"Agent enrolled successfully as device {_id.DeviceId}.");
                _log.Info("Enrollment complete.");
                return;
            }

            if (result is not null && result.Status == "ok")
            {
                // Server says OK but issued no token: device already enrolled
                // and holds a token we cannot read. Nothing to do but continue
                // unauthenticated and let the next check-in reissue.
                _log.Warn("Check-in succeeded without a token. Retrying.");
            }

            var wait = result?.RetryAfterSeconds is int r
                ? TimeSpan.FromSeconds(r)
                : delay;

            await SafeDelay(wait, ct);
            if (delay < TimeSpan.FromMinutes(5)) delay *= 2;
        }
    }

    // ---- 2b heartbeat ----------------------------------------------------

    private async Task HeartbeatAsync(CancellationToken ct)
    {
        var result = await _api.CheckinAsync(enrolling: false, ct);
        if (result is null) return;

        if (result.RetryAfterSeconds is int wait)
        {
            await SafeDelay(TimeSpan.FromSeconds(wait), ct);
            return;
        }

        // A token can be reissued on any check-in.
        if (result.ApiToken is { Length: > 0 } fresh && fresh != _id.Token)
        {
            _id.StoreToken(fresh);
            _log.Info("API token rotated.");
        }

        if (!string.IsNullOrEmpty(result.PolicyVersion) &&
            result.PolicyVersion != _id.PolicyVersion)
        {
            _log.Info($"Server policy_version {result.PolicyVersion} differs from local {_id.PolicyVersion}; " +
                "expecting sync_policy on next poll.");
        }
    }

    // ---- 2c poll + dispatch ---------------------------------------------

    private async Task PollAsync(CancellationToken ct)
    {
        var commands = await _api.PollCommandsAsync(ct);

        foreach (var cmd in commands)
        {
            if (ct.IsCancellationRequested) break;
            if (!string.IsNullOrEmpty(cmd.Id) && !_handledCommands.Add(cmd.Id)) continue;

            switch (cmd.CommandType)
            {
                case "run_script":
                    await HandleRunScriptAsync(cmd, ct);
                    break;

                case "sync_policy":
                    HandleSyncPolicy(cmd);
                    break;

                default:
                    _log.Info($"Ignoring unknown command type {cmd.CommandType}.");
                    _events.Add("unknown_command", "info",
                        $"Received unsupported command type '{cmd.CommandType}'.");
                    break;
            }
        }

        if (_handledCommands.Count > 5000) _handledCommands.Clear();
    }

    private async Task HandleRunScriptAsync(AgentCommand cmd, CancellationToken ct)
    {
        var content = GetPayloadString(cmd, "content");
        var runId   = GetPayloadString(cmd, "script_run_id");

        if (string.IsNullOrEmpty(content) || string.IsNullOrEmpty(runId))
        {
            _log.Warn("run_script command missing content or script_run_id.");
            return;
        }

        _log.Info($"Executing script run {runId}.");
        var outcome = await _scripts.RunAsync(content, ct);

        await _api.ReportScriptResultAsync(runId, outcome.ExitCode, outcome.OutputLog, ct);

        _events.Add(
            "script_executed",
            outcome.ExitCode == 0 ? "info" : "warning",
            $"Script run {runId} finished with exit code {outcome.ExitCode}.");
    }

    private void HandleSyncPolicy(AgentCommand cmd)
    {
        var version = GetPayloadString(cmd, "policy_version");
        if (string.IsNullOrEmpty(version)) return;

        _id.PolicyVersion = version;
        _log.Info($"Policy version set to {version}.");
        _events.Add("policy_synced", "info", $"Policy version updated to {version}.");
    }

    // ---- 2d event flush --------------------------------------------------

    private async Task FlushEventsAsync(CancellationToken ct)
    {
        _events.LogDropStats();

        while (_events.Count > 0 && !ct.IsCancellationRequested)
        {
            var batch = _events.TakeBatch();
            if (batch.Count == 0) break;

            var ok = await _api.SendEventsAsync(batch, ct);
            if (!ok)
            {
                _events.Requeue(batch);   // retry on the next tick
                break;
            }
        }
    }

    // ---- 2e telemetry flush ---------------------------------------------

    private async Task FlushTelemetryAsync(CancellationToken ct)
    {
        foreach (var type in _telemetry.PendingTypes().ToList())
        {
            if (ct.IsCancellationRequested) break;

            while (true)
            {
                var batch = _telemetry.TakeBatch(type);
                if (batch.Count == 0) break;

                // batch_id is generated once and reused across retries inside
                // SendTelemetryAsync so the server never double-counts.
                var batchId = Guid.NewGuid().ToString();

                var ok = await _api.SendTelemetryAsync(type, batchId, batch, ct);
                if (!ok)
                {
                    _telemetry.Requeue(type, batch);
                    break;
                }
            }
        }
    }

    // ---- loop scaffolding ------------------------------------------------

    private async Task Loop(
        string name, int intervalSeconds, Func<CancellationToken, Task> body, CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(intervalSeconds);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await body(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.Warn($"Loop {name} error: {ex.Message}");
            }

            await SafeDelay(interval, ct);
        }
    }

    private static async Task SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct); }
        catch (OperationCanceledException) { }
    }

    private static string? GetPayloadString(AgentCommand cmd, string name)
    {
        try
        {
            if (cmd.Payload.ValueKind != JsonValueKind.Object) return null;
            if (!cmd.Payload.TryGetProperty(name, out var v)) return null;
            return v.ValueKind switch
            {
                JsonValueKind.String => v.GetString(),
                JsonValueKind.Number => v.ToString(),
                _ => null
            };
        }
        catch { return null; }
    }
}
