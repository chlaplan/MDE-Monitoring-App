using System;
using System.IO;

namespace MDE_Monitoring_App
{
    public sealed class CommandLineOptions
    {
        public bool Silent { get; set; }
        public string? Target { get; set; }
        public bool? UsePsExec { get; set; }
        public string? PsExecPath { get; set; }
        public string? ExportPdfPath { get; set; }
        public string? StatusJsonPath { get; set; }
        [Obsolete("ForceRefresh is only honored in interactive (non-silent) mode.")]
        public bool ForceRefresh { get; set; }
        public int TimeoutSeconds { get; set; } = 30;
        public bool IgnoreErrors { get; set; }
        public bool ShowHelp { get; set; }

        // New: file containing machine names (txt or csv)
        public string? MachinesFilePath { get; set; }

        // New: directory to export per-machine PDF reports
        public string? ExportPdfDirectory { get; set; }

        public static CommandLineOptions Parse(string[] args)
        {
            var opts = new CommandLineOptions();
            string? lastFlag = null;

            foreach (var raw in args)
            {
                var a = raw.Trim();
                if (a.StartsWith("--"))
                {
                    lastFlag = null;
                    switch (a)
                    {
                        case "--help":
                        case "--usage":
                            opts.ShowHelp = true; break;
                        case "--silent":
                            opts.Silent = true; break;
                        case "--force-refresh":
                            opts.ForceRefresh = true; break;
                        case "--use-psexec":
                            opts.UsePsExec = true; break;
                        case "--no-psexec":
                            opts.UsePsExec = false; break;
                        case "--ignore-errors":
                            opts.IgnoreErrors = true; break;
                        default:
                            if (a.Contains('='))
                            {
                                var parts = a.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
                                SetValue(opts, parts[0], parts[1]);
                            }
                            else
                            {
                                lastFlag = a;
                            }
                            break;
                    }
                }
                else if (lastFlag != null)
                {
                    SetValue(opts, lastFlag, a);
                    lastFlag = null;
                }
            }

            return opts;
        }

        private static void SetValue(CommandLineOptions o, string flag, string value)
        {
            var v = value.Trim().Trim('"');
            switch (flag)
            {
                case "--target":          o.Target = v; break;
                case "--export-pdf":      o.ExportPdfPath = v; break;
                case "--status-json":     o.StatusJsonPath = v; break;
                case "--machines-file":   o.MachinesFilePath = v; break;
                case "--export-dir":      o.ExportPdfDirectory = v; break;
                case "--timeout":
                    if (int.TryParse(v, out var t) && t > 0 && t <= 600)
                        o.TimeoutSeconds = t;
                    break;
                case "--use-psexec":
                    o.UsePsExec = true;
                    if (!string.IsNullOrWhiteSpace(v))
                        o.PsExecPath = v;
                    break;
                case "--psexec-path":
                    o.PsExecPath = v;
                    break;
            }
        }

        public static string Usage =>
@"MDE Monitoring App switches:
  --help                       Display this help and exit.
  --silent                     Run without UI (console progress).
  --target <host>              Remote target (default localhost).
  --use-psexec                 Enable PsExec fallback (requires path).
  --use-psexec=<path>          Enable PsExec and set executable path.
  --psexec-path <path>         Specify PsExec.exe path when using --use-psexec.
  --no-psexec                  Force WinRM / PowerShell only.
  --export-pdf <file>          Generate single PDF report to path.
  --status-json <file>         Write minimal JSON status.
  --machines-file <file>       Text/CSV of machine names (requires --silent + --export-dir).
  --export-dir <dir>           Directory for per-machine PDF reports (with --machines-file).
  --timeout <seconds>          Max wait for initial refresh (default 30).
  --ignore-errors              Suppress non-zero exit codes.
  (Deprecated UI only) --force-refresh  Perform an extra refresh in interactive mode.

Per-machine report naming (with --machines-file): <machine>_<UTCyyyyMMdd_HHmmss>.pdf

Examples (interactive single/local):
  MDE-Monitor.exe
  MDE-Monitor.exe --target WS10

Examples (silent single host):
  MDE-Monitor.exe --silent --target SERVER1 --export-pdf C:\out\SERVER1_report.pdf
  MDE-Monitor.exe --silent --target SERVER2 --status-json status.json

Examples (PsExec usage):
  MDE-Monitor.exe --silent --target SERVER2 --use-psexec=C:\Tools\PsExec.exe --export-pdf C:\out\SERVER2.pdf
  MDE-Monitor.exe --silent --target SERVER3 --use-psexec --psexec-path ""D:\Sysinternals\PsExec.exe"" --status-json s3.json

Examples (batch list of machines):
  MDE-Monitor.exe --silent --machines-file hosts.txt --export-dir C:\BatchReports
  MDE-Monitor.exe --silent --machines-file list.csv --export-dir Reports --ignore-errors
  MDE-Monitor.exe --silent --machines-file servers.txt --export-dir C:\Reports --use-psexec --psexec-path ""D:\Sysinternals\PsExec.exe""

Examples (timeout tuning):
  MDE-Monitor.exe --silent --target SRV1 --timeout 120 --export-pdf C:\out\SRV1.pdf
";
    }
}