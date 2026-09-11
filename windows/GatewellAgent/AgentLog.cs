using System.Text;

namespace GatewellAgent;

/// <summary>
/// The agent's logger. Replaces Microsoft.Extensions.Logging and
/// System.Diagnostics.EventLog with a size-rotating file under ProgramData plus
/// a best-effort Windows Event Log entry through advapi32.
///
/// Nothing here ever receives the API token, enrollment token, or ORG_ID —
/// callers are responsible for keeping secrets out of log messages.
/// </summary>
public sealed class AgentLog
{
    private const long MaxBytes = 5 * 1024 * 1024;
    private const int MaxFiles = 3;

    private readonly object _gate = new();
    private readonly string _dir;
    private readonly bool _echoToConsole;
    private readonly bool _debug;

    public AgentLog(string dir, bool echoToConsole)
    {
        _dir = dir;
        _echoToConsole = echoToConsole;
        _debug = Environment.GetEnvironmentVariable("GATEWELL_DEBUG") == "1";

        try { Directory.CreateDirectory(_dir); } catch { }
    }

    public void Debug(string message)
    {
        if (_debug) Write("Debug", message);
    }

    public void Info(string message) => Write("Information", message);
    public void Warn(string message) => Write("Warning", message);
    public void Error(string message) => Write("Error", message);

    private void Write(string level, string message)
    {
        var line = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fffZ} [{level,-11}] {message}";

        if (_echoToConsole)
        {
            try { Console.WriteLine(line); } catch { }
        }

        lock (_gate)
        {
            try
            {
                var path = Path.Combine(_dir, "agent.log");
                var fi = new FileInfo(path);
                if (fi.Exists && fi.Length > MaxBytes) Rotate(path);
                File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
            }
            catch { /* logging must never throw */ }
        }

        // Warnings and errors also go to the Event Log so an MSP sees them
        // without opening a file on the endpoint.
        if (level is "Warning" or "Error" or "Information")
            Native.EventLogWrite(message, level);
    }

    private static void Rotate(string path)
    {
        try
        {
            var oldest = $"{path}.{MaxFiles}";
            if (File.Exists(oldest)) File.Delete(oldest);

            for (var i = MaxFiles - 1; i >= 1; i--)
            {
                var src = $"{path}.{i}";
                if (File.Exists(src)) File.Move(src, $"{path}.{i + 1}", true);
            }
            File.Move(path, $"{path}.1", true);
        }
        catch { }
    }
}
