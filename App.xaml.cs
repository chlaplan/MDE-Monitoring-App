using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Runtime.InteropServices;

namespace MDE_Monitoring_App
{
    public partial class App : Application
    {
        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(int dwProcessId);
        private const int ATTACH_PARENT_PROCESS = -1;

        private static void SafeConsole(string msg)
        {
            try { Console.WriteLine($"[{DateTime.UtcNow:HH:mm:ss}] {msg}"); } catch { }
        }

        protected override async void OnStartup(StartupEventArgs e)
        {
            var opts = CommandLineOptions.Parse(e.Args);

            if (opts.ShowHelp)
            {
                AttachConsole(ATTACH_PARENT_PROCESS);
                Console.WriteLine(CommandLineOptions.Usage);
                Shutdown();
                return;
            }

            if (!opts.Silent)
            {
                // Interactive mode unchanged.
                base.OnStartup(e);
                var win = new MainWindow();
                win.Show();

                if (opts.ForceRefresh)
                {
                    SafeConsole("Note: --force-refresh deprecated for silent mode; running extra refresh (UI).");
                    if (win.DataContext is MainViewModel vmInteractive)
                        _ = vmInteractive.RefreshDataAsync();
                }
                return;
            }

            AttachConsole(ATTACH_PARENT_PROCESS);
            SafeConsole("Silent mode starting...");
            base.OnStartup(e);

            // Batch mode: machines-file + export-dir
            if (!string.IsNullOrWhiteSpace(opts.MachinesFilePath))
            {
                if (string.IsNullOrWhiteSpace(opts.ExportPdfDirectory))
                {
                    SafeConsole("ERROR: --machines-file requires --export-dir.");
                    Environment.ExitCode = 8;
                    Shutdown();
                    return;
                }

                if (!File.Exists(opts.MachinesFilePath))
                {
                    SafeConsole($"ERROR: machines file not found: {opts.MachinesFilePath}");
                    Environment.ExitCode = 9;
                    Shutdown();
                    return;
                }

                try
                {
                    Directory.CreateDirectory(opts.ExportPdfDirectory);
                }
                catch (Exception ex)
                {
                    SafeConsole("ERROR: cannot create export directory: " + ex.Message);
                    Environment.ExitCode = 10;
                    Shutdown();
                    return;
                }

                SafeConsole($"Loading machines from: {opts.MachinesFilePath}");
                var raw = File.ReadAllText(opts.MachinesFilePath);
                var machines = raw.Split(new[] { '\r', '\n', ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries);

                if (machines.Length == 0)
                {
                    SafeConsole("No machine names found in file.");
                    Environment.ExitCode = 11;
                    Shutdown();
                    return;
                }

                SafeConsole($"Found {machines.Length} machine(s). Beginning batch export...");

                int failures = 0;
                foreach (var m in machines)
                {
                    var host = m.Trim();
                    if (host.Length == 0) continue;

                    SafeConsole($"Processing {host}...");
                    var vm = new MainViewModel
                    {
                        TargetMachine = host
                    };

                    if (opts.UsePsExec.HasValue)
                        vm.UsePsExec = opts.UsePsExec.Value;
                    if (vm.UsePsExec && !string.IsNullOrWhiteSpace(opts.PsExecPath))
                        vm.PsExecPath = opts.PsExecPath!;

                    var startRefresh = DateTime.UtcNow;
                    while (vm.IsBusy && (DateTime.UtcNow - startRefresh) < TimeSpan.FromSeconds(opts.TimeoutSeconds))
                        await Task.Delay(250);

                    if (vm.IsBusy)
                        SafeConsole($"WARN: Initial refresh timed out for {host} after {opts.TimeoutSeconds}s.");

                    var fileName = $"{host}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pdf";
                    var fullPath = Path.Combine(opts.ExportPdfDirectory, fileName);
                    SafeConsole($"Exporting PDF: {fullPath}");

                    try
                    {
                        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(opts.TimeoutSeconds));
                        var ok = await vm.ExportPdfAsync(fullPath, cts.Token);
                        if (ok)
                            SafeConsole($"SUCCESS: {host} PDF exported.");
                        else
                        {
                            SafeConsole($"ERROR: {host} PDF export failed.");
                            failures++;
                            if (!opts.IgnoreErrors) Environment.ExitCode = 12;
                        }
                    }
                    catch (Exception ex)
                    {
                        SafeConsole($"ERROR: {host} PDF export exception: {ex.Message}");
                        failures++;
                        if (!opts.IgnoreErrors) Environment.ExitCode = 13;
                    }
                }

                SafeConsole(failures == 0
                    ? "Batch completed successfully."
                    : $"Batch completed with {failures} failure(s). ExitCode={Environment.ExitCode}");

                Shutdown();
                return;
            }

            // Original single-target silent flow (unchanged except guarded against machines-file usage).
            var vmSingle = new MainViewModel();

            if (!string.IsNullOrWhiteSpace(opts.Target))
            {
                vmSingle.TargetMachine = opts.Target;
                SafeConsole($"Target: {vmSingle.TargetMachine}");
            }

            if (opts.UsePsExec.HasValue)
                vmSingle.UsePsExec = opts.UsePsExec.Value;

            if (vmSingle.UsePsExec)
            {
                if (!string.IsNullOrWhiteSpace(opts.PsExecPath))
                    vmSingle.PsExecPath = opts.PsExecPath!;
                if (!File.Exists(vmSingle.PsExecPath))
                {
                    SafeConsole($"ERROR: PsExec path not found: {vmSingle.PsExecPath}");
                    if (!opts.IgnoreErrors)
                    {
                        Environment.ExitCode = 6;
                        SafeConsole("Exiting due to missing PsExec path.");
                        Shutdown();
                        return;
                    }
                    else
                    {
                        SafeConsole("Continuing without PsExec due to --ignore-errors.");
                        vmSingle.UsePsExec = false;
                    }
                }
                else
                {
                    SafeConsole($"PsExec enabled: {vmSingle.PsExecPath}");
                }
            }

            SafeConsole("Waiting for initial data refresh...");
            var start = DateTime.UtcNow;
            while (vmSingle.IsBusy && (DateTime.UtcNow - start) < TimeSpan.FromSeconds(opts.TimeoutSeconds))
                await Task.Delay(250);

            if (vmSingle.IsBusy)
                SafeConsole($"Initial refresh timed out after {opts.TimeoutSeconds}s.");
            else
                SafeConsole("Initial refresh completed.");

            if (!string.IsNullOrWhiteSpace(opts.ExportPdfPath))
            {
                SafeConsole($"Preparing PDF export: {opts.ExportPdfPath}");
                try
                {
                    var dir = Path.GetDirectoryName(opts.ExportPdfPath);
                    if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                        SafeConsole($"Created directory: {dir}");
                    }

                    var cts = new CancellationTokenSource(TimeSpan.FromSeconds(opts.TimeoutSeconds));
                    var ok = await vmSingle.ExportPdfAsync(opts.ExportPdfPath, cts.Token);
                    if (ok) SafeConsole("PDF export succeeded.");
                    else
                    {
                        SafeConsole("PDF export failed.");
                        if (!opts.IgnoreErrors) Environment.ExitCode = 2;
                    }
                }
                catch (Exception ex)
                {
                    SafeConsole("PDF export error: " + ex.Message);
                    if (!opts.IgnoreErrors) Environment.ExitCode = 3;
                }
            }

            if (!string.IsNullOrWhiteSpace(opts.StatusJsonPath))
            {
                SafeConsole($"Writing status JSON: {opts.StatusJsonPath}");
                try
                {
                    var json = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        Target = vmSingle.TargetMachine,
                        Remote = vmSingle.IsRemote,
                        Platform = vmSingle.PlatformStatusText,
                        Engine = vmSingle.EngineStatusText,
                        Tamper = vmSingle.DefenderStatus.TamperProtectionDisplay,
                        Intune = vmSingle.IntuneEnrollmentDisplay,
                        WfpFilters = vmSingle.WfpFilterCount,
                        GeneratedUtc = DateTime.UtcNow
                    }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

                    var dir = Path.GetDirectoryName(opts.StatusJsonPath);
                    if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                        SafeConsole($"Created directory: {dir}");
                    }

                    File.WriteAllText(opts.StatusJsonPath, json);
                    SafeConsole("Status JSON written.");
                }
                catch (Exception ex)
                {
                    SafeConsole("Status JSON error: " + ex.Message);
                    if (!opts.IgnoreErrors) Environment.ExitCode = 4;
                }
            }

            SafeConsole(Environment.ExitCode == 0
                ? "Process completed successfully."
                : $"Process completed with exit code {Environment.ExitCode}.");
            Shutdown();
        }
    }
}
