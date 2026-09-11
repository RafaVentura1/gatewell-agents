using System.Runtime.Versioning;

// The agent targets net8.0 rather than net8.0-windows so it restores and
// compiles without the Microsoft.WindowsDesktop.App reference pack, keeping the
// project free of NuGet dependencies. It is still Windows-only at runtime, so
// declare that explicitly: this is what lets the platform-compatibility
// analyzer (CA1416) validate the P/Invoke and registry calls correctly instead
// of warning that they are reachable everywhere.
[assembly: SupportedOSPlatform("windows")]
