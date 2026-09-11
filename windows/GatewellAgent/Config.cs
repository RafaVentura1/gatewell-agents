namespace GatewellAgent;

/// <summary>
/// Build-time configuration.
///
/// CI CONTRACT: build-windows.yml performs a plain string replace on the
/// double-underscore placeholder in the OrgId constant below, substituting the
/// workflow's org_id input before `dotnet publish` runs. Do not reformat that
/// line or wrap it in anything that would break a literal text replace.
/// </summary>
public static class Config
{
    // ---- Stamped at build time by CI -------------------------------------
    public const string OrgId = "__ORG_ID__";

    // Optional: stamped the same way if/when per-org enrollment tokens are
    // issued. Left as a placeholder so the replace step can target it too.
    public const string EnrollmentToken = "__ENROLLMENT_TOKEN__";

    // ---- Static platform configuration -----------------------------------
    public const string ApiBase =
        "https://gatewell-329446a6.base44.app/functions";

    public const string AgentVersion = "1.0.0";
    public const string OsType = "windows";

    // ---- Timing ----------------------------------------------------------
    public const int HeartbeatIntervalSeconds = 60;
    public const int PollIntervalSeconds = 30;
    public const int EventFlushIntervalSeconds = 60;
    public const int TelemetryFlushIntervalSeconds = 120;
    public const int TelemetrySampleIntervalSeconds = 15;
    public const int ScriptTimeoutSeconds = 1800;

    // ---- Batch limits (server-enforced) ----------------------------------
    public const int MaxEventsPerBatch = 100;
    public const int MaxTelemetryPerBatch = 200;

    // ---- Local state -----------------------------------------------------
    public static string DataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Gatewell");

    public static string DeviceIdPath => Path.Combine(DataDir, "device_id");
    public static string TokenPath    => Path.Combine(DataDir, "api_token.dat");
    public static string PolicyPath   => Path.Combine(DataDir, "policy_version");
    public static string LogDir       => Path.Combine(DataDir, "logs");

    /// <summary>True when CI has stamped a real org id over the placeholder.</summary>
    public static bool IsStamped =>
        !OrgId.StartsWith("__", StringComparison.Ordinal);
}
