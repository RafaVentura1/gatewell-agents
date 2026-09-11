using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GatewellAgent;

public sealed record CheckinResult(
    string Status,
    string PolicyVersion,
    string? ApiToken,
    bool TokenIssued,
    int? RetryAfterSeconds);

public sealed class AgentCommand
{
    [JsonPropertyName("id")]           public string Id { get; set; } = "";
    [JsonPropertyName("command_type")] public string CommandType { get; set; } = "";
    [JsonPropertyName("payload")]      public JsonElement Payload { get; set; }
}

/// <summary>
/// All platform I/O. Every call is failure-tolerant: the caller gets a null or
/// empty result rather than an exception, and the agent keeps running.
/// </summary>
public sealed class ApiClient
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly DeviceIdentity _id;
    private readonly AgentLog _log;

    public ApiClient(HttpClient http, DeviceIdentity id, AgentLog log)
    {
        _http = http;
        _id = id;
        _log = log;
        _http.Timeout = TimeSpan.FromSeconds(30);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"GatewellAgent/{Config.AgentVersion} (windows)");
    }

    // ---- 2a / 2b : agentCheckin -----------------------------------------

    /// <summary>
    /// Enrollment (first run) and heartbeat share this endpoint. Enrollment
    /// includes enrollment_token and no Bearer; heartbeat sends the Bearer and
    /// omits enrollment_token.
    /// </summary>
    public async Task<CheckinResult?> CheckinAsync(bool enrolling, CancellationToken ct)
    {
        var body = new Dictionary<string, object?>
        {
            ["device_id"]              = _id.DeviceId,
            ["org_id"]                 = Config.OrgId,
            ["hostname"]               = _id.Hostname,
            ["os_type"]                = Config.OsType,
            ["os_version"]             = _id.OsVersion,
            ["agent_version"]          = Config.AgentVersion,
            ["ip_address"]             = DeviceIdentity.LocalIpAddress(),
            ["policy_version_current"] = _id.PolicyVersion
        };

        if (enrolling)
            body["enrollment_token"] = Config.EnrollmentToken;

        using var req = BuildRequest(HttpMethod.Post, "agentCheckin", body, auth: !enrolling);

        try
        {
            using var resp = await _http.SendAsync(req, ct);
            var text = await resp.Content.ReadAsStringAsync(ct);

            if (resp.StatusCode == (HttpStatusCode)429)
            {
                var wait = TryReadInt(text, "retry_after_seconds") ?? 60;
                _log.Warn($"Check-in rate limited, backing off {wait}s.");
                return new CheckinResult("rate_limited", _id.PolicyVersion, null, false, wait);
            }

            if (!resp.IsSuccessStatusCode)
            {
                _log.Warn($"Check-in HTTP {(int)resp.StatusCode}.");
                return null;
            }

            // A proxy or gateway in front of the platform can return an HTML
            // error page with a 200. Guard the parser rather than surfacing a
            // confusing JSON exception.
            if (!LooksLikeJson(text))
            {
                _log.Warn($"Check-in returned a non-JSON body ({text.Length} bytes).");
                return null;
            }

            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;

            return new CheckinResult(
                Status:        GetString(root, "status") ?? "ok",
                PolicyVersion: GetString(root, "policy_version") ?? _id.PolicyVersion,
                ApiToken:      GetString(root, "api_token"),
                TokenIssued:   root.TryGetProperty("token_issued", out var t) &&
                               t.ValueKind == JsonValueKind.True,
                RetryAfterSeconds: null);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.Warn($"Check-in failed: {ex.Message}");
            return null;
        }
    }

    // ---- 2c : agentPollCommands -----------------------------------------

    public async Task<List<AgentCommand>> PollCommandsAsync(CancellationToken ct)
    {
        var url = $"{Config.ApiBase}/agentPollCommands?device_id={Uri.EscapeDataString(_id.DeviceId)}";
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        AddAuth(req);

        try
        {
            using var resp = await _http.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode)
            {
                _log.Debug($"Poll HTTP {(int)resp.StatusCode}.");
                return new List<AgentCommand>();
            }

            var text = await resp.Content.ReadAsStringAsync(ct);
            if (!LooksLikeJson(text)) return new List<AgentCommand>();

            return JsonSerializer.Deserialize<List<AgentCommand>>(text, Json)
                   ?? new List<AgentCommand>();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.Warn($"Poll failed: {ex.Message}");
            return new List<AgentCommand>();
        }
    }

    // ---- 2c : agentScriptResult -----------------------------------------

    public Task<bool> ReportScriptResultAsync(
        string scriptRunId, int exitCode, string outputLog, CancellationToken ct)
    {
        var body = new Dictionary<string, object?>
        {
            ["script_run_id"] = scriptRunId,
            ["device_id"]     = _id.DeviceId,
            ["exit_code"]     = exitCode,
            ["output_log"]    = Truncate(outputLog, 64 * 1024)
        };
        return PostWithRetryAsync("agentScriptResult", body, ct);
    }

    // ---- 2d : agentEvents ------------------------------------------------

    public Task<bool> SendEventsAsync(IReadOnlyList<object> batch, CancellationToken ct)
    {
        if (batch.Count == 0) return Task.FromResult(true);
        var body = new Dictionary<string, object?>
        {
            ["device_id"] = _id.DeviceId,
            ["batch"]     = batch
        };
        return PostWithRetryAsync("agentEvents", body, ct);
    }

    // ---- 2e : agentTelemetry --------------------------------------------

    /// <summary>
    /// batch_id is the idempotency key. The caller generates it once per batch
    /// and passes the SAME value on retry so the server never double-counts.
    /// </summary>
    public Task<bool> SendTelemetryAsync(
        string telemetryType, string batchId, IReadOnlyList<object> batch, CancellationToken ct)
    {
        if (batch.Count == 0) return Task.FromResult(true);
        var body = new Dictionary<string, object?>
        {
            ["device_id"]      = _id.DeviceId,
            ["telemetry_type"] = telemetryType,
            ["batch_id"]       = batchId,
            ["batch"]          = batch
        };
        return PostWithRetryAsync("agentTelemetry", body, ct);
    }

    // ---- internals -------------------------------------------------------

    private HttpRequestMessage BuildRequest(
        HttpMethod method, string fn, object body, bool auth)
    {
        var req = new HttpRequestMessage(method, $"{Config.ApiBase}/{fn}")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(body, Json), Encoding.UTF8, "application/json")
        };
        if (auth) AddAuth(req);
        return req;
    }

    private void AddAuth(HttpRequestMessage req)
    {
        if (_id.HasToken)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _id.Token);
    }

    /// <summary>Three attempts with exponential backoff. Never throws.</summary>
    private async Task<bool> PostWithRetryAsync(
        string fn, Dictionary<string, object?> body, CancellationToken ct)
    {
        var delay = TimeSpan.FromSeconds(2);

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var req = BuildRequest(HttpMethod.Post, fn, body, auth: true);
                using var resp = await _http.SendAsync(req, ct);

                if (resp.IsSuccessStatusCode) return true;

                if (resp.StatusCode == (HttpStatusCode)429)
                {
                    var text = await resp.Content.ReadAsStringAsync(ct);
                    var wait = TryReadInt(text, "retry_after_seconds") ?? 60;
                    _log.Warn($"{fn} rate limited, waiting {wait}s.");
                    await Task.Delay(TimeSpan.FromSeconds(wait), ct);
                    continue;
                }

                // 4xx other than 429 will not succeed on retry.
                if ((int)resp.StatusCode is >= 400 and < 500)
                {
                    _log.Warn($"{fn} rejected with HTTP {(int)resp.StatusCode}.");
                    return false;
                }

                _log.Debug($"{fn} HTTP {(int)resp.StatusCode}, attempt {attempt}.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _log.Debug($"{fn} attempt {attempt} failed: {ex.Message}");
            }

            if (attempt < 3)
            {
                await Task.Delay(delay, ct);
                delay *= 2;
            }
        }
        return false;
    }

    private static string? GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : root.TryGetProperty(name, out var n) && n.ValueKind == JsonValueKind.Number
                ? n.ToString()
                : null;

    private static int? TryReadInt(string json, string name)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty(name, out var v) &&
                v.ValueKind == JsonValueKind.Number)
                return v.GetInt32();
        }
        catch { }
        return null;
    }

    /// <summary>
    /// True when the body plausibly starts a JSON object or array, so an HTML
    /// or plaintext error page is never handed to the parser.
    /// </summary>
    private static bool LooksLikeJson(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.AsSpan().TrimStart();
        return t.Length > 0 && (t[0] == '{' || t[0] == '[');
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max
            ? s
            : s[..max] + "\n[...truncated]";
}
