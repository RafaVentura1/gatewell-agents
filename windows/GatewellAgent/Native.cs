using System.Runtime.InteropServices;
using System.Text;

namespace GatewellAgent;

/// <summary>
/// Direct OS interop that replaces three NuGet packages the agent would
/// otherwise need. Keeping these as P/Invoke means the project depends only on
/// the BCL and restores with no network access.
///
///   System.Security.Cryptography.ProtectedData -> Dpapi
///   Microsoft.Win32.Registry                   -> NativeRegistry
///   System.Diagnostics.EventLog                -> NativeEventLog
/// </summary>
internal static class Native
{
    // ================= DPAPI (crypt32.dll) =================================

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;
    private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn, string? szDataDescr, ref DataBlob pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn, IntPtr ppszDataDescr, ref DataBlob pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DataBlob pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    /// <summary>Encrypt under the machine key. Equivalent to
    /// ProtectedData.Protect(..., DataProtectionScope.LocalMachine).</summary>
    public static byte[] Protect(byte[] plain, byte[] entropy)
    {
        var inBlob = default(DataBlob);
        var entBlob = default(DataBlob);
        var outBlob = default(DataBlob);

        var inHandle = GCHandle.Alloc(plain, GCHandleType.Pinned);
        var entHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
        try
        {
            inBlob.cbData = plain.Length;
            inBlob.pbData = inHandle.AddrOfPinnedObject();
            entBlob.cbData = entropy.Length;
            entBlob.pbData = entHandle.AddrOfPinnedObject();

            if (!CryptProtectData(
                    ref inBlob, null, ref entBlob, IntPtr.Zero, IntPtr.Zero,
                    CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                    out outBlob))
                throw new InvalidOperationException(
                    $"CryptProtectData failed ({Marshal.GetLastWin32Error()})");

            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            if (inHandle.IsAllocated) inHandle.Free();
            if (entHandle.IsAllocated) entHandle.Free();
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
        }
    }

    /// <summary>Decrypt data produced by <see cref="Protect"/>.</summary>
    public static byte[] Unprotect(byte[] cipher, byte[] entropy)
    {
        var inBlob = default(DataBlob);
        var entBlob = default(DataBlob);
        var outBlob = default(DataBlob);

        var inHandle = GCHandle.Alloc(cipher, GCHandleType.Pinned);
        var entHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
        try
        {
            inBlob.cbData = cipher.Length;
            inBlob.pbData = inHandle.AddrOfPinnedObject();
            entBlob.cbData = entropy.Length;
            entBlob.pbData = entHandle.AddrOfPinnedObject();

            if (!CryptUnprotectData(
                    ref inBlob, IntPtr.Zero, ref entBlob, IntPtr.Zero, IntPtr.Zero,
                    CRYPTPROTECT_UI_FORBIDDEN, out outBlob))
                throw new InvalidOperationException(
                    $"CryptUnprotectData failed ({Marshal.GetLastWin32Error()})");

            var result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            if (inHandle.IsAllocated) inHandle.Free();
            if (entHandle.IsAllocated) entHandle.Free();
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
        }
    }

    // ================= Registry (advapi32.dll) =============================

    private static readonly IntPtr HKEY_LOCAL_MACHINE = new(unchecked((int)0x80000002));

    private const int KEY_READ = 0x20019;
    private const int KEY_WRITE = 0x20006;
    private const int REG_SZ = 1;
    private const int ERROR_SUCCESS = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegCreateKeyExW(
        IntPtr hKey, string lpSubKey, int Reserved, string? lpClass, int dwOptions,
        int samDesired, IntPtr lpSecurityAttributes, out IntPtr phkResult,
        out int lpdwDisposition);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyExW(
        IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegSetValueExW(
        IntPtr hKey, string lpValueName, int Reserved, int dwType,
        byte[] lpData, int cbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryValueExW(
        IntPtr hKey, string lpValueName, IntPtr lpReserved, out int lpType,
        byte[]? lpData, ref int lpcbData);

    [DllImport("advapi32.dll")]
    private static extern int RegCloseKey(IntPtr hKey);

    /// <summary>Read a REG_SZ value from HKLM, or null if absent.</summary>
    public static string? RegistryRead(string subKey, string valueName)
    {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, out var hKey)
            != ERROR_SUCCESS)
            return null;

        try
        {
            var size = 0;
            if (RegQueryValueExW(hKey, valueName, IntPtr.Zero, out _, null, ref size)
                != ERROR_SUCCESS || size <= 0)
                return null;

            var buffer = new byte[size];
            if (RegQueryValueExW(hKey, valueName, IntPtr.Zero, out _, buffer, ref size)
                != ERROR_SUCCESS)
                return null;

            return Encoding.Unicode.GetString(buffer).TrimEnd('\0');
        }
        finally { RegCloseKey(hKey); }
    }

    /// <summary>Write a REG_SZ value to HKLM, creating the key if needed.</summary>
    public static bool RegistryWrite(string subKey, string valueName, string value)
    {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, null, 0, KEY_WRITE,
                IntPtr.Zero, out var hKey, out _) != ERROR_SUCCESS)
            return false;

        try
        {
            var data = Encoding.Unicode.GetBytes(value + "\0");
            return RegSetValueExW(hKey, valueName, 0, REG_SZ, data, data.Length)
                   == ERROR_SUCCESS;
        }
        finally { RegCloseKey(hKey); }
    }

    // ================= Event Log (advapi32.dll) ============================

    private const ushort EVENTLOG_SUCCESS_TYPE = 0x0000;
    private const ushort EVENTLOG_ERROR_TYPE = 0x0001;
    private const ushort EVENTLOG_WARNING_TYPE = 0x0002;
    private const ushort EVENTLOG_INFORMATION_TYPE = 0x0004;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterEventSourceW(string? lpUNCServerName, string lpSourceName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ReportEventW(
        IntPtr hEventLog, ushort wType, ushort wCategory, uint dwEventID,
        IntPtr lpUserSid, ushort wNumStrings, uint dwDataSize,
        string[] lpStrings, IntPtr lpRawData);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeregisterEventSource(IntPtr hEventLog);

    private static IntPtr _eventSource = IntPtr.Zero;

    /// <summary>
    /// Register the event source and ensure the Application log knows about it.
    /// Safe to call repeatedly; failures are swallowed since the rotating file
    /// log is the primary sink.
    /// </summary>
    public static void EventLogInit(string sourceName)
    {
        try
        {
            RegistryWrite(
                $@"SYSTEM\CurrentControlSet\Services\EventLog\Application\{sourceName}",
                "EventMessageFile",
                @"%SystemRoot%\System32\EventCreate.exe");

            _eventSource = RegisterEventSourceW(null, sourceName);
        }
        catch { _eventSource = IntPtr.Zero; }
    }

    /// <summary>Write one entry. No-op if the source could not be registered.</summary>
    public static void EventLogWrite(string message, string level)
    {
        if (_eventSource == IntPtr.Zero) return;

        var type = level switch
        {
            "Error" => EVENTLOG_ERROR_TYPE,
            "Warning" => EVENTLOG_WARNING_TYPE,
            "Information" => EVENTLOG_INFORMATION_TYPE,
            _ => EVENTLOG_SUCCESS_TYPE
        };

        try
        {
            ReportEventW(_eventSource, type, 0, 1000, IntPtr.Zero, 1, 0,
                new[] { message }, IntPtr.Zero);
        }
        catch { /* logging must never throw */ }
    }

    public static void EventLogClose()
    {
        if (_eventSource == IntPtr.Zero) return;
        try { DeregisterEventSource(_eventSource); } catch { }
        _eventSource = IntPtr.Zero;
    }
}
