using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace GatewellAgent;

/// <summary>
/// Owns the machine-scoped identity of this agent: a stable device_id, the API
/// token issued at enrollment, and the last known policy version.
///
/// The device_id is written to both HKLM and a ProgramData file so an agent
/// reinstall that clears one still recovers the same identity from the other.
/// The API token is encrypted at rest with DPAPI under the machine key and is
/// never written to any log.
/// </summary>
public sealed class DeviceIdentity
{
    private const string RegKey = @"SOFTWARE\Gatewell\Agent";
    private const string RegValue = "DeviceId";

    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("Gatewell.Agent.TokenStore.v1");

    private readonly AgentLog _log;
    private string? _token;

    public string DeviceId { get; private set; } = "";
    public string Hostname { get; private set; } = "";
    public string OsVersion { get; private set; } = "";

    public DeviceIdentity(AgentLog log) => _log = log;

    public void Initialize()
    {
        Directory.CreateDirectory(Config.DataDir);
        Directory.CreateDirectory(Config.LogDir);
        HardenDirectory(Config.DataDir);

        Hostname  = SafeHostname();
        OsVersion = Environment.OSVersion.Version.ToString();
        DeviceId  = LoadOrCreateDeviceId();
        _token    = LoadToken();

        _log.Info(
            $"Identity ready. device_id={DeviceId} host={Hostname} " +
            $"os={OsVersion} token_present={_token is not null}");
    }

    // ---- device_id -------------------------------------------------------

    private string LoadOrCreateDeviceId()
    {
        var fromReg  = SafeRegRead();
        var fromFile = ReadFileSafe(Config.DeviceIdPath);

        var existing = fromReg ?? fromFile;
        if (!string.IsNullOrWhiteSpace(existing))
        {
            // Heal whichever store was missing.
            if (fromReg is null) SafeRegWrite(existing);
            if (fromFile is null) WriteFileSafe(Config.DeviceIdPath, existing);
            return existing;
        }

        var generated = Guid.NewGuid().ToString();
        SafeRegWrite(generated);
        WriteFileSafe(Config.DeviceIdPath, generated);
        _log.Info("Generated new device_id.");
        return generated;
    }

    private string? SafeRegRead()
    {
        try { return Native.RegistryRead(RegKey, RegValue); }
        catch (Exception ex) { _log.Debug($"Registry read failed: {ex.Message}"); return null; }
    }

    private void SafeRegWrite(string value)
    {
        try
        {
            if (!Native.RegistryWrite(RegKey, RegValue, value))
                _log.Debug("Registry device_id write returned false.");
        }
        catch (Exception ex) { _log.Warn($"Registry write failed: {ex.Message}"); }
    }

    // ---- API token (DPAPI, machine scope) --------------------------------

    public string? Token => _token;
    public bool HasToken => !string.IsNullOrEmpty(_token);

    public void StoreToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        try
        {
            var cipher = Native.Protect(Encoding.UTF8.GetBytes(token), Entropy);
            File.WriteAllBytes(Config.TokenPath, cipher);
            HardenFile(Config.TokenPath);
            _token = token;
            _log.Info("API token stored."); // value intentionally omitted
        }
        catch (Exception ex)
        {
            _log.Error($"Failed to store API token: {ex.Message}");
        }
    }

    private string? LoadToken()
    {
        try
        {
            if (!File.Exists(Config.TokenPath)) return null;
            var plain = Native.Unprotect(File.ReadAllBytes(Config.TokenPath), Entropy);
            var s = Encoding.UTF8.GetString(plain);
            return string.IsNullOrWhiteSpace(s) ? null : s;
        }
        catch (Exception ex)
        {
            _log.Warn($"Stored token unreadable, will re-enroll: {ex.Message}");
            return null;
        }
    }

    // ---- policy version --------------------------------------------------

    public string PolicyVersion
    {
        get => ReadFileSafe(Config.PolicyPath) ?? "0";
        set => WriteFileSafe(Config.PolicyPath, value);
    }

    // ---- helpers ---------------------------------------------------------

    public static string LocalIpAddress()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.IsLoopback(ip.Address))
                        return ip.Address.ToString();
                }
            }
        }
        catch { /* non-fatal */ }
        return "0.0.0.0";
    }

    private static string SafeHostname()
    {
        try { return Environment.MachineName; } catch { return "unknown"; }
    }

    private string? ReadFileSafe(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var s = File.ReadAllText(path).Trim();
            return string.IsNullOrWhiteSpace(s) ? null : s;
        }
        catch (Exception ex)
        {
            _log.Debug($"Read {path} failed: {ex.Message}");
            return null;
        }
    }

    private void WriteFileSafe(string path, string value)
    {
        try
        {
            File.WriteAllText(path, value);
            HardenFile(path);
        }
        catch (Exception ex)
        {
            _log.Warn($"Write {path} failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Restrict the state directory to SYSTEM and Administrators. Uses icacls
    /// rather than System.Security.AccessControl, which is a NuGet package on
    /// .NET 8 and would break the BCL-only constraint.
    /// </summary>
    private static void HardenDirectory(string path) =>
        RunIcacls($"\"{path}\" /inheritance:r /grant:r SYSTEM:(OI)(CI)F Administrators:(OI)(CI)F");

    private static void HardenFile(string path) =>
        RunIcacls($"\"{path}\" /inheritance:r /grant:r SYSTEM:F Administrators:F");

    private static void RunIcacls(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "icacls",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            p?.WaitForExit(10_000);
        }
        catch { /* best effort */ }
    }
}
