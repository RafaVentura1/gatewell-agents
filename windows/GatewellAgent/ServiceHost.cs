using System.Runtime.InteropServices;

namespace GatewellAgent;

/// <summary>
/// Minimal Windows Service host built directly on the Service Control Manager
/// APIs. This replaces Microsoft.Extensions.Hosting.WindowsServices so the
/// agent has no NuGet dependencies.
///
/// Two modes:
///   service  - StartServiceCtrlDispatcher hands control to the SCM, which
///              calls ServiceMain on a dedicated thread.
///   console  - run in the foreground for local testing (--console), with
///              Ctrl+C mapped to the same cancellation token.
/// </summary>
public sealed class ServiceHost
{
    private const int SERVICE_WIN32_OWN_PROCESS = 0x00000010;

    private const int SERVICE_STOPPED = 0x00000001;
    private const int SERVICE_START_PENDING = 0x00000002;
    private const int SERVICE_STOP_PENDING = 0x00000003;
    private const int SERVICE_RUNNING = 0x00000004;

    private const int SERVICE_ACCEPT_STOP = 0x00000001;
    private const int SERVICE_ACCEPT_SHUTDOWN = 0x00000004;

    private const int SERVICE_CONTROL_STOP = 0x00000001;
    private const int SERVICE_CONTROL_SHUTDOWN = 0x00000005;
    private const int SERVICE_CONTROL_INTERROGATE = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public int dwServiceType;
        public int dwCurrentState;
        public int dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string lpServiceName;
        public IntPtr lpServiceProc;
    }

    private delegate void ServiceMainDelegate(int argc, IntPtr argv);
    private delegate int HandlerExDelegate(
        int control, int eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool StartServiceCtrlDispatcherW(ServiceTableEntry[] lpServiceTable);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerExW(
        string lpServiceName, HandlerExDelegate lpHandlerProc, IntPtr lpContext);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceStatus(IntPtr hServiceStatus, ref ServiceStatus lpServiceStatus);

    private readonly string _serviceName;
    private readonly Func<CancellationToken, Task> _body;
    private readonly AgentLog _log;

    private readonly CancellationTokenSource _cts = new();
    private IntPtr _statusHandle = IntPtr.Zero;
    private ServiceStatus _status;

    // Held as fields so the GC cannot collect the delegates while the SCM
    // still holds native function pointers to them.
    private ServiceMainDelegate? _serviceMain;
    private HandlerExDelegate? _handler;

    public ServiceHost(string serviceName, Func<CancellationToken, Task> body, AgentLog log)
    {
        _serviceName = serviceName;
        _body = body;
        _log = log;
    }

    /// <summary>Run under the SCM. Returns false if not started as a service.</summary>
    public bool RunAsService()
    {
        _serviceMain = ServiceMain;

        var table = new[]
        {
            new ServiceTableEntry
            {
                lpServiceName = _serviceName,
                lpServiceProc = Marshal.GetFunctionPointerForDelegate(_serviceMain)
            },
            new ServiceTableEntry { lpServiceName = null!, lpServiceProc = IntPtr.Zero }
        };

        // Returns false with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063)
        // when the process was launched from a console rather than the SCM.
        return StartServiceCtrlDispatcherW(table);
    }

    /// <summary>Run in the foreground, Ctrl+C to stop.</summary>
    public async Task RunAsConsoleAsync()
    {
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _log.Info("Ctrl+C received, shutting down.");
            _cts.Cancel();
        };

        await SafeBodyAsync();
    }

    private void ServiceMain(int argc, IntPtr argv)
    {
        _handler = HandlerEx;
        _statusHandle = RegisterServiceCtrlHandlerExW(_serviceName, _handler, IntPtr.Zero);

        if (_statusHandle == IntPtr.Zero)
        {
            _log.Error($"RegisterServiceCtrlHandlerEx failed ({Marshal.GetLastWin32Error()}).");
            return;
        }

        _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        _status.dwServiceSpecificExitCode = 0;

        Report(SERVICE_START_PENDING, waitHint: 10_000);
        Report(SERVICE_RUNNING);

        try
        {
            SafeBodyAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _log.Error($"Service body terminated unexpectedly: {ex.Message}");
        }
        finally
        {
            Report(SERVICE_STOPPED);
            Native.EventLogClose();
        }
    }

    private int HandlerEx(int control, int eventType, IntPtr eventData, IntPtr context)
    {
        switch (control)
        {
            case SERVICE_CONTROL_STOP:
            case SERVICE_CONTROL_SHUTDOWN:
                _log.Info("Stop requested by the service control manager.");
                Report(SERVICE_STOP_PENDING, waitHint: 15_000);
                _cts.Cancel();
                break;

            case SERVICE_CONTROL_INTERROGATE:
                Report(_status.dwCurrentState);
                break;
        }
        return 0; // NO_ERROR
    }

    private void Report(int state, int waitHint = 0)
    {
        if (_statusHandle == IntPtr.Zero) return;

        _status.dwCurrentState = state;
        _status.dwWin32ExitCode = 0;
        _status.dwWaitHint = waitHint;
        _status.dwControlsAccepted = state == SERVICE_START_PENDING
            ? 0
            : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

        // Checkpoint must advance while a pending state is reported.
        _status.dwCheckPoint = state is SERVICE_START_PENDING or SERVICE_STOP_PENDING
            ? _status.dwCheckPoint + 1
            : 0;

        SetServiceStatus(_statusHandle, ref _status);
    }

    /// <summary>
    /// The agent body must never take the process down. Any escaped exception
    /// is logged and swallowed so the SCM sees a clean stop.
    /// </summary>
    private async Task SafeBodyAsync()
    {
        try
        {
            await _body(_cts.Token);
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        catch (Exception ex)
        {
            _log.Error($"Unhandled agent exception: {ex}");
        }
    }
}
