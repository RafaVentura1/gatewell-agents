using System.Diagnostics;
using System.Text;

namespace GatewellAgent;

public sealed record ScriptOutcome(int ExitCode, string OutputLog);

/// <summary>
/// Writes a run_script payload to a temp .ps1, executes it under PowerShell as
/// the service account (SYSTEM), captures combined stdout+stderr, and always
/// deletes the temp file.
/// </summary>
public sealed class ScriptRunner
{
    private readonly AgentLog _log;

    public ScriptRunner(AgentLog log) => _log = log;

    public async Task<ScriptOutcome> RunAsync(string content, CancellationToken ct)
    {
        var temp = Path.Combine(
            Path.GetTempPath(), $"gw_{Guid.NewGuid():N}.ps1");

        try
        {
            await File.WriteAllTextAsync(temp, content, new UTF8Encoding(false), ct);

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments =
                    "-NonInteractive -NoProfile -ExecutionPolicy Bypass " +
                    $"-File \"{temp}\"",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };

            var sb = new StringBuilder();
            var gate = new object();

            using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };

            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                lock (gate) sb.AppendLine(e.Data);
            };
            proc.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                lock (gate) sb.AppendLine("[stderr] " + e.Data);
            };

            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(Config.ScriptTimeoutSeconds));

            try
            {
                await proc.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                TryKill(proc);
                lock (gate)
                    sb.AppendLine($"[timeout] exceeded {Config.ScriptTimeoutSeconds}s");
                return new ScriptOutcome(-1, sb.ToString());
            }

            string output;
            lock (gate) output = sb.ToString();

            _log.Info($"Script finished with exit code {proc.ExitCode}.");
            return new ScriptOutcome(proc.ExitCode, output);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log.Error($"Script execution error: {ex.Message}");
            return new ScriptOutcome(-2, $"[error] {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private static void TryKill(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
    }
}
