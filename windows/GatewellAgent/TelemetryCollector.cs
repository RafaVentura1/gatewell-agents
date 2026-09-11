using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace GatewellAgent;

/// <summary>
/// Phase-1 EDR telemetry using only the BCL. Sampled rather than event-driven:
/// a periodic snapshot is diffed against the previous one so the footprint
/// stays small on end-user machines.
///
///   process  — new process starts (name, path, cmdline, parent, sha256)
///   registry — additions/changes under known persistence run-keys
///   network  — established TCP connections with owning PID
///
/// Executable hashing is capped per cycle and cached by path+size so we never
/// spend meaningful CPU on it. ETW/WMI would give true event-driven capture and
/// is the intended phase-2 upgrade.
/// </summary>
public sealed class TelemetryCollector
{
    private const int MaxHashesPerCycle = 10;
    private const int MaxNewProcessesPerCycle = 50;
    private const int QueueCapacity = 4000;

    private static readonly string[] RunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SYSTEM\CurrentControlSet\Services"
    };

    private readonly AgentLog _log;
    private readonly ConcurrentQueue<(string Type, Dictionary<string, object?> Event)> _queue = new();
    private readonly Dictionary<string, string> _hashCache = new(StringComparer.OrdinalIgnoreCase);

    private HashSet<int> _knownPids = new();
    private Dictionary<string, string> _knownRunValues = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _knownConnections = new(StringComparer.OrdinalIgnoreCase);
    private bool _primed;

    public TelemetryCollector(AgentLog log) => _log = log;

    public int Count => _queue.Count;

    /// <summary>One sampling pass. Never throws.</summary>
    public void Sample()
    {
        try { SampleProcesses(); }  catch (Exception ex) { _log.Debug($"proc sample: {ex.Message}"); }
        try { SampleRunKeys(); }    catch (Exception ex) { _log.Debug($"reg sample: {ex.Message}"); }
        try { SampleNetwork(); }    catch (Exception ex) { _log.Debug($"net sample: {ex.Message}"); }
        _primed = true;
    }

    public List<object> TakeBatch(string telemetryType)
    {
        var batch = new List<object>(Config.MaxTelemetryPerBatch);
        var carry = new List<(string, Dictionary<string, object?>)>();

        while (batch.Count < Config.MaxTelemetryPerBatch && _queue.TryDequeue(out var item))
        {
            if (item.Type == telemetryType) batch.Add(item.Event);
            else carry.Add(item);
        }
        foreach (var c in carry) _queue.Enqueue(c);
        return batch;
    }

    public void Requeue(string telemetryType, IEnumerable<object> batch)
    {
        foreach (var e in batch)
            if (e is Dictionary<string, object?> d)
                Enqueue(telemetryType, d);
    }

    public IEnumerable<string> PendingTypes()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (type, _) in _queue) seen.Add(type);
        return seen;
    }

    // ---- process ---------------------------------------------------------

    private void SampleProcesses()
    {
        var current = new HashSet<int>();
        var procs = Process.GetProcesses();
        var hashed = 0;

        foreach (var p in procs)
        {
            try
            {
                current.Add(p.Id);
                if (!_primed || _knownPids.Contains(p.Id)) continue;
                if (current.Count > MaxNewProcessesPerCycle + _knownPids.Count) continue;

                var path = SafeExePath(p);
                var evt = new Dictionary<string, object?>
                {
                    ["event_id"]    = Guid.NewGuid().ToString(),
                    ["timestamp"]   = DateTime.UtcNow.ToString("o"),
                    ["kind"]        = "process_start",
                    ["pid"]         = p.Id,
                    ["name"]        = SafeName(p),
                    ["path"]        = path,
                    ["command_line"]= null, // requires WMI/NtQuery; phase 2
                    ["parent_pid"]  = SafeParentPid(p.Id),
                    ["sha256"]      = hashed < MaxHashesPerCycle && path is not null
                                        ? HashOf(path, ref hashed)
                                        : null
                };
                Enqueue("process", evt);
            }
            catch { /* process may have exited mid-enumeration */ }
            finally { p.Dispose(); }
        }

        _knownPids = current;
    }

    private string? HashOf(string path, ref int budget)
    {
        if (_hashCache.TryGetValue(path, out var cached)) return cached;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length > 64L * 1024 * 1024) return null;

            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            var hash = Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();

            budget++;
            if (_hashCache.Count < 2000) _hashCache[path] = hash;
            return hash;
        }
        catch { return null; }
    }

    // ---- registry --------------------------------------------------------

    private void SampleRunKeys()
    {
        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var keyPath in RunKeys)
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key is null) continue;

            // Services hive is large: only track the ImagePath of each service.
            if (keyPath.EndsWith("Services", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var sub in key.GetSubKeyNames())
                {
                    using var svc = key.OpenSubKey(sub);
                    var img = svc?.GetValue("ImagePath") as string;
                    if (img is not null)
                        current[$@"HKLM\{keyPath}\{sub}\ImagePath"] = img;
                }
                continue;
            }

            foreach (var name in key.GetValueNames())
                current[$@"HKLM\{keyPath}\{name}"] = key.GetValue(name)?.ToString() ?? "";
        }

        if (_primed)
        {
            foreach (var (k, v) in current)
            {
                if (_knownRunValues.TryGetValue(k, out var old) && old == v) continue;
                Enqueue("registry", new Dictionary<string, object?>
                {
                    ["event_id"]  = Guid.NewGuid().ToString(),
                    ["timestamp"] = DateTime.UtcNow.ToString("o"),
                    ["kind"]      = _knownRunValues.ContainsKey(k) ? "value_modified" : "value_added",
                    ["key"]       = k,
                    ["value"]     = Trim(v, 512)
                });
            }
        }

        _knownRunValues = current;
    }

    // ---- network ---------------------------------------------------------

    private void SampleNetwork()
    {
        var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in GetTcpTable())
        {
            var key = $"{row.Pid}|{row.Remote}";
            current.Add(key);
            if (!_primed || _knownConnections.Contains(key)) continue;

            Enqueue("network", new Dictionary<string, object?>
            {
                ["event_id"]    = Guid.NewGuid().ToString(),
                ["timestamp"]   = DateTime.UtcNow.ToString("o"),
                ["kind"]        = "tcp_connect",
                ["pid"]         = row.Pid,
                ["process_name"]= SafeNameByPid(row.Pid),
                ["local"]       = row.Local,
                ["remote_ip"]   = row.RemoteIp,
                ["remote_port"] = row.RemotePort
            });
        }

        _knownConnections = current;
    }

    private readonly record struct TcpRow(
        int Pid, string Local, string Remote, string RemoteIp, int RemotePort);

    /// <summary>
    /// GetExtendedTcpTable via IP Helper. Gives PID-attributed connections
    /// without shelling out and without a third-party dependency.
    /// </summary>
    private static IEnumerable<TcpRow> GetTcpTable()
    {
        const int AF_INET = 2;
        const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;

        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET,
            TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET,
                    TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != 0)
                yield break;

            var count = Marshal.ReadInt32(buf);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var ptr = IntPtr.Add(buf, 4);

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(ptr);
                ptr = IntPtr.Add(ptr, rowSize);

                var remoteIp = new System.Net.IPAddress(BitConverter.GetBytes(row.RemoteAddr)).ToString();
                if (remoteIp == "0.0.0.0") continue;

                // Ports arrive in network byte order in the low 16 bits.
                var remotePort = (int)(((row.RemotePort & 0xFF) << 8) | ((row.RemotePort >> 8) & 0xFF));
                var localIp    = new System.Net.IPAddress(BitConverter.GetBytes(row.LocalAddr)).ToString();
                var localPort  = (int)(((row.LocalPort & 0xFF) << 8) | ((row.LocalPort >> 8) & 0xFF));

                yield return new TcpRow(
                    (int)row.OwningPid,
                    $"{localIp}:{localPort}",
                    $"{remoteIp}:{remotePort}",
                    remoteIp,
                    remotePort);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, int tableClass, int reserved);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr h, int cls, ref ProcessBasicInformation info, int len, out int ret);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    // ---- helpers ---------------------------------------------------------

    private void Enqueue(string type, Dictionary<string, object?> evt)
    {
        while (_queue.Count >= QueueCapacity && _queue.TryDequeue(out _)) { }
        _queue.Enqueue((type, evt));
    }

    private static string? SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return null; }
    }

    private static string? SafeNameByPid(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.ProcessName; }
        catch { return null; }
    }

    private static string? SafeExePath(Process p)
    {
        try { return p.MainModule?.FileName; } catch { return null; }
    }

    private static int? SafeParentPid(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var info = new ProcessBasicInformation();
            var rc = NtQueryInformationProcess(
                p.Handle, 0, ref info, Marshal.SizeOf(info), out _);
            return rc == 0 ? (int)info.InheritedFromUniqueProcessId : null;
        }
        catch { return null; }
    }

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max];
}
