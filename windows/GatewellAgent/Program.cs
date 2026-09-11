using GatewellAgent;

// Entry point. Runs under the Windows Service Control Manager by default and
// in the foreground with --console for local testing.
//
// There is no generic host: Microsoft.Extensions.Hosting is a NuGet package and
// the agent is deliberately BCL-only, so ServiceHost talks to the SCM directly.

var console = args.Contains("--console", StringComparer.OrdinalIgnoreCase)
              || args.Contains("-c", StringComparer.OrdinalIgnoreCase);

Native.EventLogInit("GatewellAgent");

var log = new AgentLog(Config.LogDir, echoToConsole: console);

// Composition root — plain construction, no DI container.
var identity  = new DeviceIdentity(log);
var http      = new HttpClient();
var api       = new ApiClient(http, identity, log);
var scripts   = new ScriptRunner(log);
var events    = new EventBuffer(log);
var telemetry = new TelemetryCollector(log);
var worker    = new AgentWorker(log, identity, api, scripts, events, telemetry);

var host = new ServiceHost("GatewellAgent", worker.RunAsync, log);

if (console)
{
    log.Info("Starting in console mode. Press Ctrl+C to stop.");
    await host.RunAsConsoleAsync();
    Native.EventLogClose();
    return 0;
}

if (!host.RunAsService())
{
    // 1063 = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: not launched by the SCM.
    var err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    if (err == 1063)
    {
        Console.Error.WriteLine(
            "GatewellAgent must be started by the Windows Service Control Manager.\n" +
            "For local testing run:  GatewellAgent.exe --console");
        Native.EventLogClose();
        return 1;
    }

    log.Error($"StartServiceCtrlDispatcher failed ({err}).");
    Native.EventLogClose();
    return err;
}

return 0;
