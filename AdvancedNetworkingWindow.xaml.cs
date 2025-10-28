using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using System.Linq;

namespace MDE_Monitoring_App
{
    public partial class AdvancedNetworkingWindow : Window
    {
        private readonly AdvancedNetworkingViewModel _vm;
        private CancellationTokenSource? _cts;
        private CancellationTokenSource? _dropCts;

        private readonly string _targetMachine;
        private readonly bool _usePsExec;
        private readonly string? _psExecPath;

        // New constructor overload
        public AdvancedNetworkingWindow(string targetMachine, bool usePsExec, string? psExecPath)
        {
            InitializeComponent();
            _vm = new AdvancedNetworkingViewModel();
            DataContext = _vm;

            _targetMachine = targetMachine.Trim();
            _usePsExec = usePsExec;
            _psExecPath = psExecPath;

            if (!string.IsNullOrWhiteSpace(_targetMachine) &&
                !_targetMachine.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
                !_targetMachine.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(_vm.TraceFilePath) ||
                    _vm.TraceFilePath.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase))
                {
                    var safe = @"C:\Windows\Temp\nettrace_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".etl";
                    _vm.TraceFilePath = safe;
                    AppendStatus("Remote target detected. Adjusted trace file path to: " + safe);
                }
            }

            Loaded += AdvancedNetworkingWindow_Loaded;
        }

        public AdvancedNetworkingWindow() : this("localhost", false, null) { }

        private async void AdvancedNetworkingWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await CheckExistingTraceAsync();
        }

        private async Task CheckExistingTraceAsync()
        {
            AppendStatus("Checking existing netsh trace status...");
            var output = await GetNetshOutputAsync("trace show status", CancellationToken.None);

            if (string.IsNullOrWhiteSpace(output))
            {
                AppendStatus("No status output received.");
                return;
            }

            var running = Regex.IsMatch(output, @"^Status:\s+Running", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            var fileMatch = Regex.Match(output, @"^Trace File:\s+(.*)$", RegexOptions.Multiline | RegexOptions.IgnoreCase);

            if (running)
            {
                _vm.IsTracing = true;
                AppendStatus("Existing trace detected (already running). UI set to tracing state.");
                if (fileMatch.Success)
                    AppendStatus("Existing trace file: " + fileMatch.Groups[1].Value.Trim());
            }
            else
            {
                AppendStatus("No existing trace running.");
            }
        }

        private void BrowseTracePath_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Title = "Select trace output file",
                Filter = "ETL Trace|*.etl",
                FileName = $"nettrace_{DateTime.Now:yyyyMMdd_HHmm}.etl"
            };
            if (dlg.ShowDialog(this) == true)
                _vm.TraceFilePath = dlg.FileName;
        }

        private void StartDropMonitorIfNeeded()
        {
            if (!_vm.IsTracing) return;
            if (!_vm.StopAfterFirewallDrop && !_vm.StopAfterFilteredDrop) return;
            if (_dropCts != null) return;
            _dropCts = new CancellationTokenSource();
            AppendStatus("Starting firewall drop monitor...");
            StartDropMonitorTask(_dropCts.Token);
        }

        private void StopDropMonitor()
        {
            if (_dropCts == null) return;
            AppendStatus("Stopping firewall drop monitor...");
            try { _dropCts.Cancel(); } catch { }
            _dropCts.Dispose();
            _dropCts = null;
        }

        private string GetFirewallLogPath()
        {
            // Default Windows Firewall log location (assuming logging enabled)
            return IsLocalTarget()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "LogFiles", "Firewall", "pfirewall.log")
                : $@"\\{_targetMachine}\c$\Windows\System32\LogFiles\Firewall\pfirewall.log";
        }

        private async Task<bool> EnsureFirewallLoggingEnabledAsync()
        {
            var path = GetFirewallLogPath();
            if (File.Exists(path)) return true;

            AppendStatus("Firewall log not found; attempting to enable dropped connections logging...");

            var cmd = "advfirewall set currentprofile logging droppedconnections enable";
            bool ok;
            if (IsLocalTarget())
            {
                ok = await RunNetshAsync(cmd, CancellationToken.None);
            }
            else
            {
                ok = await RunNetshAsync(cmd, CancellationToken.None);
            }

            AppendStatus(ok
                ? "Requested firewall dropped connections logging enable."
                : "Failed to enable firewall dropped connections logging.");

            if (!File.Exists(path))
                AppendStatus("Firewall log still not present; monitoring will retry.");

            return File.Exists(path);
        }

        private void ParseAndProcessFirewallLine(string line)
        {
            if (!line.Contains("DROP", StringComparison.OrdinalIgnoreCase)) return;

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 8) { AppendStatus("DROP line too short: " + line); return; }

            var dropIndex = Array.FindIndex(parts, p => p.Equals("DROP", StringComparison.OrdinalIgnoreCase));
            if (dropIndex < 0 || dropIndex + 5 >= parts.Length)
            {
                AppendStatus("DROP layout unexpected: " + line);
                return;
            }

            var protocol = parts[dropIndex + 1];
            var srcIp = parts[dropIndex + 2];
            var dstIp = parts[dropIndex + 3];
            if (!int.TryParse(parts[dropIndex + 4], out var srcPort)) srcPort = 0;
            if (!int.TryParse(parts[dropIndex + 5], out var dstPort)) dstPort = 0;

            ProcessFirewallDrop(srcIp, dstIp, srcPort, dstPort);
        }

        protected override void OnClosed(EventArgs e)
        {
            try
            {
                StopDropMonitor();
                if (_vm.IsTracing)
                    Dispatcher.BeginInvoke(new Action(async () => await StopTraceInternalAsync()));
                _cts?.Cancel();
            }
            catch { }
            base.OnClosed(e);
        }

        private void StartDropMonitorTask(CancellationToken token)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await EnsureFirewallLoggingEnabledAsync().ConfigureAwait(false);
                    var path = GetFirewallLogPath();
                    long lastPos = 0;
                    DateTime lastMissingReport = DateTime.MinValue;
                    var regex = new Regex(@"\bDROP\b.*?(?<src>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst>\d{1,3}(?:\.\d{1,3}){3})\s+(?<sport>\d+)\s+(?<dport>\d+)", RegexOptions.IgnoreCase);

                    while (!token.IsCancellationRequested && _vm.IsTracing)
                    {
                        if (!File.Exists(path))
                        {
                            if ((DateTime.UtcNow - lastMissingReport) > TimeSpan.FromSeconds(30))
                            {
                                AppendStatus("Firewall log file not found (monitor waiting): " + path);
                                lastMissingReport = DateTime.UtcNow;
                            }
                            await Task.Delay(2000, token).ConfigureAwait(false);
                            continue;
                        }

                        try
                        {
                            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            if (lastPos > fs.Length) lastPos = 0; // log rotated
                            fs.Seek(lastPos, SeekOrigin.Begin);
                            using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                            while (!sr.EndOfStream && !token.IsCancellationRequested)
                            {
                                var line = await sr.ReadLineAsync().ConfigureAwait(false);
                                if (line == null) break;
                                if (line.IndexOf("DROP", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    var m = regex.Match(line);
                                    if (m.Success)
                                    {
                                        if (int.TryParse(m.Groups["sport"].Value, out var sp) &&
                                            int.TryParse(m.Groups["dport"].Value, out var dp))
                                        {
                                            // Dispatch to UI thread
                                            Dispatcher.Invoke(() =>
                                                ProcessFirewallDrop(m.Groups["src"].Value,
                                                                    m.Groups["dst"].Value,
                                                                    sp, dp));
                                        }
                                        else
                                        {
                                            Dispatcher.Invoke(() =>
                                                AppendStatus("DROP parsed without valid ports: " + line));
                                        }
                                    }
                                    else
                                    {
                                        Dispatcher.Invoke(() => AppendStatus("DROP (unparsed): " + line));
                                    }
                                }
                            }
                            lastPos = fs.Position;
                        }
                        catch (IOException ex)
                        {
                            Dispatcher.Invoke(() => AppendStatus("Drop monitor IO error: " + ex.Message));
                            await Task.Delay(1500, token).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() => AppendStatus("Drop monitor error: " + ex.Message));
                            await Task.Delay(3000, token).ConfigureAwait(false);
                        }

                        await Task.Delay(750, token).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => AppendStatus("Drop monitor fatal error: " + ex.Message));
                }
            }, token);
        }

        private async void StartTrace_Click(object sender, RoutedEventArgs e)
        {
            if (_vm.IsTracing) return;

            if (IsRemoteTarget() &&
                (_vm.TraceFilePath.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase) ||
                 _vm.TraceFilePath.Contains("Desktop", StringComparison.OrdinalIgnoreCase)))
            {
                var safe = @"C:\Windows\Temp\nettrace_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".etl";
                AppendStatus("Replacing unsuitable remote path with: " + safe);
                _vm.TraceFilePath = safe;
            }

            if (!IsRemoteTarget() && !IsElevated())
            {
                AppendStatus("ERROR: Trace requires elevated privileges (run as Administrator).");
                return;
            }

            if (string.IsNullOrWhiteSpace(_vm.TraceFilePath))
            {
                AppendStatus("ERROR: Specify an output trace file.");
                return;
            }

            if (IsRemoteTarget() && _vm.TraceFilePath.Contains("Desktop", StringComparison.OrdinalIgnoreCase))
                AppendStatus("WARNING: Avoid Desktop path on remote SYSTEM. Adjusted automatically if needed.");

            try
            {
                if (!IsRemoteTarget())
                    Directory.CreateDirectory(Path.GetDirectoryName(_vm.TraceFilePath)!);
            }
            catch (Exception ex)
            {
                AppendStatus("ERROR: Cannot create directory: " + ex.Message);
                return;
            }

            var args = BuildStartArgs();
            AppendStatus("Starting: netsh " + args);
            _cts = new CancellationTokenSource();

            var startOk = await RunNetshAsync(args, _cts.Token);
            if (startOk)
            {
                _vm.IsTracing = true;
                AppendStatus("Trace started.");
                StartDropMonitorIfNeeded();
            }
            else
            {
                _vm.IsTracing = false;
                AppendStatus("Failed to start trace.");
                _cts.Dispose();
                _cts = null;
                return;
            }

            if (_vm.IsTracing && _vm.DurationSeconds > 0)
            {
                _ = Task.Run(async () =>
                {
                    AppendStatus($"Duration timer: {_vm.DurationSeconds} seconds.");
                    try { await Task.Delay(TimeSpan.FromSeconds(_vm.DurationSeconds), _cts!.Token).ConfigureAwait(false); }
                    catch (TaskCanceledException) { }
                    if (_vm.IsTracing && !_cts!.IsCancellationRequested)
                    {
                        AppendStatus("Duration elapsed. Stopping trace...");
                        Dispatcher.Invoke(async () => await StopTraceInternalAsync());
                    }
                });
            }
        }

        private async Task StopTraceInternalAsync()
        {
            if (!_vm.IsTracing)
                return;
            StopDropMonitor();
            AppendStatus("Stopping trace...");
            _cts?.Cancel();

            var args = "trace stop";
            AppendStatus("Running: netsh " + args);
            var stopOk = await RunNetshAsync(args, CancellationToken.None);
            if (stopOk)
            {
                _vm.IsTracing = false;
                AppendStatus("Trace stopped.");
            }
            else
            {
                AppendStatus("Failed to stop trace.");
            }

            _cts?.Dispose();
            _cts = null;
        }

        private async void StopTrace_Click(object sender, RoutedEventArgs e) =>
            await StopTraceInternalAsync();

        private void SimulateFirewallDrop_Click(object sender, RoutedEventArgs e)
        {
            if (!_vm.IsTracing)
            {
                AppendStatus("Simulation ignored (not tracing).");
                return;
            }
            ProcessFirewallDrop("10.1.1.5", "203.0.113.8", 51515, 443);
        }

        private void ProcessFirewallDrop(string srcIp, string dstIp, int srcPort, int dstPort)
        {
            AppendStatus($"Firewall drop detected src={srcIp}:{srcPort} dst={dstIp}:{dstPort}");

            bool trigger = false;

            if (_vm.StopAfterFirewallDrop)
            {
                trigger = true;
                AppendStatus("Unconditional stop-after-first-drop enabled.");
            }
            else if (_vm.StopAfterFilteredDrop)
            {
                bool ipSrcOk = string.IsNullOrWhiteSpace(_vm.MatchSourceIp) || srcIp.Equals(_vm.MatchSourceIp, StringComparison.OrdinalIgnoreCase);
                bool ipDstOk = string.IsNullOrWhiteSpace(_vm.MatchDestIp) || dstIp.Equals(_vm.MatchDestIp, StringComparison.OrdinalIgnoreCase);
                bool portSrcOk = !_vm.MatchSourcePort.HasValue || _vm.MatchSourcePort.Value == srcPort;
                bool portDstOk = !_vm.MatchDestPort.HasValue || _vm.MatchDestPort.Value == dstPort;

                if (ipSrcOk && ipDstOk && portSrcOk && portDstOk)
                {
                    trigger = true;
                    AppendStatus("Drop matches filter criteria; scheduling stop.");
                }
                else
                {
                    AppendStatus("Drop did not match filter criteria; continuing trace.");
                }
            }

            if (trigger)
            {
                AppendStatus("Will stop in 10 seconds...");
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(10));
                    Dispatcher.Invoke(async () =>
                    {
                        if (_vm.IsTracing)
                            await StopTraceInternalAsync();
                    });
                });
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private string BuildStartArgs()
        {
            var sb = new StringBuilder("trace start");
            if (_vm.CaptureYes) sb.Append(" capture=yes");
            if (_vm.ReportYes) sb.Append(" report=yes");
            sb.Append($" tracefile=\"{_vm.TraceFilePath}\"");
            // Multi-scenario support
            var selectedScenarios = _vm.ScenarioOptions.Where(s => s.IsSelected).Select(s => s.Name).ToList();
            if (selectedScenarios.Count > 0)
                sb.Append($" scenario={string.Join(",", selectedScenarios)}");
            // Multi-provider support
            var selectedProviders = _vm.Providers.Where(p => p.IsSelected).ToList();
            if (selectedProviders.Count > 0)
            {
                foreach (var provider in selectedProviders)
                {
                    if (!string.IsNullOrWhiteSpace(provider.Name))
                        sb.Append($" provider=\"{provider.Name}\"");
                    else if (!string.IsNullOrWhiteSpace(provider.Guid))
                        sb.Append($" provider={provider.Guid}");
                }
            }
            if (_vm.MaxSizeMb > 0) sb.Append($" maxsize={_vm.MaxSizeMb}");
            if (_vm.Overwrite) sb.Append(" overwrite=yes");
            if (_vm.Persistent) sb.Append(" persistent=yes");
            return sb.ToString();
        }

        private async Task<string> GetNetshOutputAsync(string arguments, CancellationToken token)
        {
            var sb = new StringBuilder();
            try
            {
                if (IsLocalTarget())
                {
                    var psi = new ProcessStartInfo("netsh", arguments)
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
                    var tcs = new TaskCompletionSource<int>();
                    p.OutputDataReceived += (_, e) => { if (e.Data != null) { sb.AppendLine(e.Data); AppendStatus(e.Data); } };
                    p.ErrorDataReceived += (_, e) => { if (e.Data != null) { sb.AppendLine("ERR: " + e.Data); AppendStatus("ERR: " + e.Data); } };
                    p.Exited += (_, __) => tcs.TrySetResult(p.ExitCode);
                    if (!p.Start()) { AppendStatus("ERROR: netsh did not start for status query."); return sb.ToString(); }
                    p.BeginOutputReadLine(); p.BeginErrorReadLine();
                    using (token.Register(() => { try { if (!p.HasExited) p.Kill(); } catch { } }))
                        AppendStatus("netsh (status) exit code: " + await tcs.Task);
                }
                else
                {
                    if (_usePsExec)
                    {
                        if (string.IsNullOrWhiteSpace(_psExecPath) || !File.Exists(_psExecPath))
                        {
                            AppendStatus("ERROR: PsExec path invalid for status query.");
                            return sb.ToString();
                        }
                        var exe = _psExecPath.Contains(' ') ? $"\"{_psExecPath}\"" : _psExecPath;
                        var fullCmd = $"{exe} \\\\{_targetMachine} -s netsh {arguments}";
                        await CaptureProcessOutputAsync(fullCmd, null, token, sb, "REMOTE");
                    }
                    else
                    {
                        // FIX: Removed outer single quotes and use double quotes only around computer name.
                        var psScript = $"Invoke-Command -ComputerName \"{_targetMachine}\" -ScriptBlock {{ netsh {arguments} }}";
                        var psi = new ProcessStartInfo("powershell.exe",
                            $"-NoLogo -NoProfile -ExecutionPolicy Bypass -Command {psScript}")
                        {
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };
                        await CaptureProcessOutputAsync(null, psi, token, sb, "REMOTE");
                    }
                }
            }
            catch (Exception ex) { AppendStatus("EXCEPTION (status): " + ex.Message); }
            return sb.ToString();
        }

        // ADD: Output-capturing helper for remote/local status collection
        private async Task<bool> CaptureProcessOutputAsync(string? fullCommand, ProcessStartInfo? psi, CancellationToken token, StringBuilder collector, string tag)
        {
            if (psi == null)
            {
                var firstSpace = fullCommand!.IndexOf(' ');
                var exe = fullCommand.Substring(0, firstSpace);
                var args = fullCommand.Substring(firstSpace + 1);
                psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
            }

            AppendStatus($"{tag} EXEC (status): {psi.FileName} {psi.Arguments}");
            using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
            var tcs = new TaskCompletionSource<int>();

            p.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    collector.AppendLine(e.Data);
                    AppendStatus(e.Data);
                }
            };
            p.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    collector.AppendLine($"{tag} ERR: {e.Data}");
                    AppendStatus($"{tag} ERR: " + e.Data);
                }
            };
            p.Exited += (_, __) => tcs.TrySetResult(p.ExitCode);

            if (!p.Start())
            {
                AppendStatus($"{tag} ERROR: process did not start (status).");
                return false;
            }
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            using (token.Register(() => { try { if (!p.HasExited) p.Kill(); } catch { } }))
            {
                var exit = await tcs.Task;
                AppendStatus($"{tag} exit code (status): " + exit);
                return exit == 0;
            }
        }

        private async Task<bool> RunNetshAsync(string arguments, CancellationToken token)
        {
            if (IsLocalTarget())
                return await RunNetshLocalAsync(arguments, token);
            return await RunNetshRemoteAsync(arguments, token);
        }


        private bool IsLocalTarget() =>
            string.IsNullOrWhiteSpace(_targetMachine) ||
            _targetMachine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            _targetMachine.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        private bool IsRemoteTarget() => !IsLocalTarget();

        private async Task<bool> RunNetshLocalAsync(string arguments, CancellationToken token)
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", arguments)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
                var tcs = new TaskCompletionSource<int>();

                p.OutputDataReceived += (_, e) => { if (e.Data != null) AppendStatus(e.Data); };
                p.ErrorDataReceived += (_, e) => { if (e.Data != null) AppendStatus("ERR: " + e.Data); };
                p.Exited += (_, __) => tcs.TrySetResult(p.ExitCode);

                if (!p.Start())
                {
                    AppendStatus("ERROR: netsh did not start.");
                    return false;
                }
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                using (token.Register(() =>
                {
                    try { if (!p.HasExited) p.Kill(); } catch { }
                }))
                {
                    var exit = await tcs.Task;
                    AppendStatus("netsh exit code: " + exit);
                    return exit == 0;
                }
            }
            catch (Exception ex)
            {
                AppendStatus("EXCEPTION: " + ex.Message);
                return false;
            }
        }

        private async Task<bool> RunNetshRemoteAsync(string arguments, CancellationToken token)
        {
            if (_vm.TraceFilePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), StringComparison.OrdinalIgnoreCase))
                AppendStatus("NOTE: Adjust tracefile path to a remote path accessible on " + _targetMachine);

            if (_usePsExec)
            {
                if (string.IsNullOrWhiteSpace(_psExecPath) || !File.Exists(_psExecPath))
                {
                    AppendStatus("ERROR: PsExec path invalid.");
                    return false;
                }
                var exe = _psExecPath.Contains(' ') ? $"\"{_psExecPath}\"" : _psExecPath;
                var cmd = $"{exe} \\\\{_targetMachine} -s netsh {arguments}";
                return await RunProcessCaptureAsync(cmd, null, token);
            }
            else
            {
                // FIX: Same quoting adjustment as status path.
                var psScript = $"Invoke-Command -ComputerName \"{_targetMachine}\" -ScriptBlock {{ netsh {arguments} }}";
                var psi = new ProcessStartInfo("powershell.exe",
                    $"-NoLogo -NoProfile -ExecutionPolicy Bypass -Command {psScript}")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                return await RunProcessCaptureAsync(null, psi, token);
            }
        }

        private static string EscapeForRemote(string raw) => raw;



        // Helper to run either a composed single command string (PsExec) or a provided ProcessStartInfo
        private async Task<bool> RunProcessCaptureAsync(string? fullCommand, ProcessStartInfo? psi, CancellationToken token)
        {
            try
            {
                if (psi == null)
                {
                    // Split executable and args for PsExec scenario
                    var firstSpace = fullCommand!.IndexOf(' ');
                    var exe = fullCommand.Substring(0, firstSpace);
                    var args = fullCommand.Substring(firstSpace + 1);
                    psi = new ProcessStartInfo(exe, args)
                    {
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                }

                AppendStatus("REMOTE EXEC: " + psi.FileName + " " + psi.Arguments);

                using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
                var tcs = new TaskCompletionSource<int>();

                p.OutputDataReceived += (_, e) => { if (e.Data != null) AppendStatus(e.Data); };
                p.ErrorDataReceived += (_, e) => { if (e.Data != null) AppendStatus("REMOTE ERR: " + e.Data); };
                p.Exited += (_, __) => tcs.TrySetResult(p.ExitCode);

                if (!p.Start())
                {
                    AppendStatus("ERROR: Remote process did not start.");
                    return false;
                }
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                using (token.Register(() =>
                {
                    try { if (!p.HasExited) p.Kill(); } catch { }
                }))
                {
                    var exit = await tcs.Task;
                    AppendStatus("Remote exit code: " + exit);
                    return exit == 0;
                }
            }
            catch (Exception ex)
            {
                AppendStatus("REMOTE EXCEPTION: " + ex.Message);
                return false;
            }
        }

        private void AppendStatus(string line) =>
            _vm.StatusLog += $"[{DateTime.Now:HH:mm:ss}] {line}\n";

        private static bool IsElevated()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public class ScenarioOption : INotifyPropertyChanged
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected != value)
                {
                    _isSelected = value;
                    OnChanged(nameof(IsSelected));
                    IsSelectedChanged?.Invoke(this, EventArgs.Empty);
                }
            }
        }
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
        public event EventHandler? IsSelectedChanged;
    }

    public class NetshProviderInfoWithSelect : INotifyPropertyChanged
    {
        public string? Name { get; set; }
        public string? Guid { get; set; }
        public string? DefaultLevel { get; set; }
        public string? DefaultKeywords { get; set; }
        private bool _isSelected;
        public bool IsSelected { get => _isSelected; set { _isSelected = value; OnChanged(nameof(IsSelected)); } }
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    public class AdvancedNetworkingViewModel : INotifyPropertyChanged
    {
        private string _traceFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"nettrace_{DateTime.Now:yyyyMMdd_HHmm}.etl");
        private string _statusLog = "";
        private bool _captureYes = true;
        private bool _reportYes = true;
        private bool _overwrite = true;
        private bool _persistent;
        private bool _providersMicrosoftOnly;
        private bool _isTracing;
        private int _maxSizeMb = 512;
        private int _durationSeconds;
        private bool _stopAfterFirewallDrop;
        private bool _stopAfterFilteredDrop;
        private string? _matchSourceIp;
        private string? _matchDestIp;
        private int? _matchSourcePort;
        private int? _matchDestPort;

        private ObservableCollection<ScenarioOption> _scenarioOptions = new();
        private ObservableCollection<NetshProviderInfoWithSelect> _providers = new();

        // Static provider mapping for all scenarios
        private static readonly Dictionary<string, List<NetshProviderInfoWithSelect>> StaticScenarioProviders = new(StringComparer.OrdinalIgnoreCase)
        {
            ["NetConnection"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["AddressAcquisition"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["AddressAcquisitionServer"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NWiFi", Guid = "{0BD3506A-9030-4F76-9B88-3E8FE1F7CFB6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DNS-Client", Guid = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}", DefaultLevel = "3 (win:Warning)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-VWiFi", Guid = "{314B2B0D-81EE-4474-B6E0-C2AAEC0DDBDE}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinINet", Guid = "{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WebIO", Guid = "{50B3E73C-9370-461D-BB9F-26F32D68887D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-EapHost", Guid = "{6EB8DB94-FE96-443F-A366-5FE0CEE7FB1C}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinHttp", Guid = "{7D44233D-3055-4B9C-BA64-0D47CA40A232}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-L2NACP", Guid = "{85FE7609-FF4A-48E9-9D50-12918E43E1DA}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{923C0FFD-7933-4B52-8A49-121ABF2DC357}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WLAN-AutoConfig", Guid = "{9580D7DD-0379-4658-9870-D5BE7D52D6DE}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-OneX", Guid = "{AB0D8EF9-866D-4D39-B83F-453F3B8F6325}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ABB1FC61-49BA-4CC3-809F-7ABE1F8BA315}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Wired-AutoConfig", Guid = "{B92CF7FD-DC10-4C6B-A72D-1613BF25E597}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NDIS", Guid = "{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheEventProvider", Guid = "{DD85457F-4E2D-44A5-A7A7-6253362E34DC}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["DirectAccess"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Ncasvc", Guid = "{126DED58-A28D-4113-8E7A-59D7444B2AF1}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Runtime-Web-Http", Guid = "{41877CB4-11FC-4188-B590-712C143C881D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinINet", Guid = "{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WebIO", Guid = "{50B3E73C-9370-461D-BB9F-26F32D68887D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinHttp", Guid = "{7D44233D-3055-4B9C-BA64-0D47CA40A232}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{923C0FFD-7933-4B52-8A49-121ABF2DC357}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ABB1FC61-49BA-4CC3-809F-7ABE1F8BA315}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-HttpService", Guid = "{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheEventProvider", Guid = "{DD85457F-4E2D-44A5-A7A7-6253362E34DC}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheClientEventProvider", Guid = "{E837619C-A2A8-4689-833F-47B48EBD2442}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Quic", Guid = "{FF15E657-4F26-570E-88AB-0796B258D11C}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["DirectAccessServer"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Ncasvc", Guid = "{126DED58-A28D-4113-8E7A-59D7444B2AF1}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DNS-Client", Guid = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}", DefaultLevel = "3 (win:Warning)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinINet", Guid = "{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WebIO", Guid = "{50B3E73C-9370-461D-BB9F-26F32D68887D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "255", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinHttp", Guid = "{7D44233D-3055-4B9C-BA64-0D47CA40A232}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-OneX", Guid = "{AB0D8EF9-866D-4D39-B83F-453F3B8F6325}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Wired-AutoConfig", Guid = "{B92CF7FD-DC10-4C6B-A72D-1613BF25E597}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NDIS", Guid = "{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "255", DefaultKeywords = "0x0" }
            },
            ["FileSharing"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Remotefs-Rdbss", Guid = "{1A870028-F191-4699-8473-6FCD299EAB77}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-SMBClient", Guid = "{988C59C5-0A1C-45B6-A555-0C62276E327D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["InternetClient"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Runtime-Web-Http", Guid = "{41877CB4-11FC-4188-B590-712C143C881D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinINet", Guid = "{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WebIO", Guid = "{50B3E73C-9370-461D-BB9F-26F32D68887D}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WinHttp", Guid = "{7D44233D-3055-4B9C-BA64-0D47CA40A232}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{923C0FFD-7933-4B52-8A49-121ABF2DC357}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ABB1FC61-49BA-4CC3-809F-7ABE1F8BA315}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-HttpService", Guid = "{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheEventProvider", Guid = "{DD85457F-4E2D-44A5-A7A7-6253362E34DC}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheClientEventProvider", Guid = "{E837619C-A2A8-4689-833F-47B48EBD2442}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Quic", Guid = "{FF15E657-4F26-570E-88AB-0796B258D11C}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" }
            },
            ["InternetServer"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ABB1FC61-49BA-4CC3-809F-7ABE1F8BA315}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-HttpService", Guid = "{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheEventProvider", Guid = "{DD85457F-4E2D-44A5-A7A7-6253362E34DC}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-BranchCacheClientEventProvider", Guid = "{E837619C-A2A8-4689-833F-47B48EBD2442}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["NetConnection"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["NetworkSnapshot"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "", Guid = "{3C70D3E6-40C8-5875-67F3-AD429A730A44}", DefaultLevel = "5", DefaultKeywords = "0xE00000" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0xE00000" }
            },
            ["P2P-Grouping"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "", Guid = "{3333D2FC-3AEE-479F-985D-8BEBAE552B99}", DefaultLevel = "4", DefaultKeywords = "0xFFFFFFFF00000000" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0xFFFFFFFF00000000" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{BBBC81CF-E219-469C-A405-F820EE496194}", DefaultLevel = "4", DefaultKeywords = "0xFFFFFFFF00000000" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["P2P-PNRP"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0xFFFFFFFF00000000" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{BBBC81CF-E219-469C-A405-F820EE496194}", DefaultLevel = "4", DefaultKeywords = "0xFFFFFFFF00000000" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["RemoteAssistance"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-RemoteAssistance", Guid = "{5B0A651A-8807-45CC-9656-7579815B6AF0}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0xFFFFFFFF00000000" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Dhcp-Client", Guid = "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-DHCPv6-Client", Guid = "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x800000000000000A (sixto4,teredo,Microsoft-Windows-Iphlpsvc/Trace)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-MPS-SRV", Guid = "{5444519F-2484-45A2-991E-953E4B54C8E0}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (Service,Microsoft-Windows-MPS-SRV/Diagnostic,0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NCSI", Guid = "{314DE49F-CE63-4779-BA2B-D616F6963A88}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{5A8A94F3-249F-49F8-86D1-E6527C80622B}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NlaSvc", Guid = "{63B530F8-29C9-4880-A5B4-B8179096E7B8}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{EA289C62-8C36-4904-9726-15ECD282AED5}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ED795972-60E8-4815-8634-CFAA21A89DE7}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkProfile", Guid = "{FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Winsock-AFD", Guid = "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{BBBC81CF-E219-469C-A405-F820EE496194}", DefaultLevel = "4", DefaultKeywords = "0xFFFFFFFF00000000" }
            },
            ["Virtualization"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "", Guid = "{28F7FB0F-EAB3-4960-9693-9289CA768DEA}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{6066F867-7CA1-4418-85FD-36E3F9C0600C}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{67DC0D66-3695-47C0-9642-33F76F7BD7AD}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{6C28C7E5-331B-4437-9C69-5352A2F7F296}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{9F2660EA-CFE7-428F-9850-AECA612619B0}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{A6527853-5B2B-46E5-9D77-A4486E012E73}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkBridge", Guid = "{A67075C2-3E39-4109-B6CD-6D750058A731}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{B72C6994-9FE0-45AD-83B3-8F5885F20E0E}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{DBC217A8-018F-4D8E-A849-ACEA31BC93F9}", DefaultLevel = "5", DefaultKeywords = "0x0" }
            },
            ["VPNServer"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-TCPIP", Guid = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-IPSEC-SRV", Guid = "{C91EF675-842F-4FCF-A5C9-6EA93F2E4F8B}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NDIS", Guid = "{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Ras-NdisWanPacketCapture", Guid = "{D84521F7-2235-4237-A7C0-14E3A9676286}", DefaultLevel = "5 (win:Verbose)", DefaultKeywords = "0x0" }
            },
            ["WCN"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{ABB1FC61-49BA-4CC3-809F-7ABE1F8BA315}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WCN-Config-Registrar", Guid = "{C100BECF-D33A-4A4B-BF23-BBEF4663D017}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NWiFi", Guid = "{0BD3506A-9030-4F76-9B88-3E8FE1F7CFB6}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-VWiFi", Guid = "{314B2B0D-81EE-4474-B6E0-C2AAEC0DDBDE}", DefaultLevel = "5", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-L2NACP", Guid = "{85FE7609-FF4A-48E9-9D50-12918E43E1DA}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WLAN-AutoConfig", Guid = "{9580D7DD-0379-4658-9870-D5BE7D52D6DE}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" }
            },
            ["WFP-IPsec"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-WFP", Guid = "{0C478C5B-0351-41B1-8C58-4A6737DA32E3}", DefaultLevel = "4 (win:Informational)", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-NetworkSecurity", Guid = "{7B702970-90BC-4584-8B20-C0799086EE5A}", DefaultLevel = "4", DefaultKeywords = "0x0" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Windows Firewall With Advanced Security", Guid = "{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}", DefaultLevel = "5", DefaultKeywords = "0x0" }
            },
            ["XboxMultiplayer"] = new List<NetshProviderInfoWithSelect>
            {
                new NetshProviderInfoWithSelect { Name = "BFE Trace Provider", Guid = "{106B464A-8043-46B1-8CB8-E92A0CD7A560}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x10000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "IKEEXT Trace Provider", Guid = "{106B464D-8043-46B1-8CB8-E92A0CD7A560}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x10000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Windows Defender Firewall API", Guid = "{28C9F48F-D244-45A8-842F-DC9FBC9B6E92}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (TL_ERROR,TL_WARN,TL_INFO,TL_FUNC,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x10000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{514775E1-FA95-459F-B6D4-B86AD1C5B49E}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF" },
                new NetshProviderInfoWithSelect { Name = "FWPUCLNT Trace Provider", Guid = "{5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x10000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "Windows Defender Firewall Service", Guid = "{5EEFEBDB-E90C-423A-8ABF-0241E7C5B87D}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF (TL_ERROR,TL_WARN,TL_INFO,TL_FUNC,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,0x10000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000,0x10000000,0x20000000,0x40000000,0x80000000,0x100000000,0x200000000,0x400000000,0x800000000,0x1000000000,0x2000000000,0x4000000000,0x8000000000,0x10000000000,0x20000000000,0x40000000000,0x80000000000,0x100000000000,0x200000000000,0x400000000000,0x800000000000,0x1000000000000,0x2000000000000,0x4000000000000,0x8000000000000,0x10000000000000,0x20000000000000,0x40000000000000,0x80000000000000,0x100000000000000,0x200000000000000,0x400000000000000,0x800000000000000,0x1000000000000000,0x2000000000000000,0x4000000000000000,0x8000000000000000)" },
                new NetshProviderInfoWithSelect { Name = "", Guid = "{60523747-6516-48B7-84B1-3264FA2CB359}", DefaultLevel = "255", DefaultKeywords = "0xFFFFFFFFFFFFFFFF" },
                new NetshProviderInfoWithSelect { Name = "Microsoft-Windows-Iphlpsvc-Trace", Guid = "{6600E712-C3B6-44A2-8A48-935C511F28C8}", DefaultLevel = "255", DefaultKeywords = "0xF800000000000080 (teredoFailures,Microsoft-Windows-Iphlpsvc/Trace,Microsoft-Windows-Iphlpsvc/Debug,System,0x800000000000000,0x1000000000000000)" }
            }
        };

        // Scenarios
        private static readonly Dictionary<string, string> ScenarioDescriptions = new(StringComparer.OrdinalIgnoreCase)
        {
            ["AddressAcquisition"] = "Troubleshoot address acquisition related issues (e.g. DHCP, IPv4/IPv6 autoconfiguration).",
            ["AddressAcquisitionServer"] = "Troubleshoot server-side address assignment issues (DHCP server behavior).",
            ["DirectAccess"] = "Troubleshoot DirectAccess client connectivity (tunnel establishment, NRPT).",
            ["DirectAccessServer"] = "Troubleshoot DirectAccess server infrastructure (DNS64/NAT64, IPHTTPS, load balancing).",
            ["FileSharing"] = "Troubleshoot common file and printer sharing problems (SMB).",
            ["ICS"] = "Troubleshoot Internet Connection Sharing configuration and NAT forwarding.",
            ["InternetClient"] = "Troubleshoot general web connectivity (HTTP/HTTPS, proxy, name resolution).",
            ["InternetServer"] = "Troubleshoot server-side web connectivity (listener, TLS, port binding).",
            ["NetConnection"] = "Troubleshoot general network connection establishment and teardown issues.",
            ["NetworkSnapshot"] = "Collect a point-in-time snapshot of current network stack and state.",
            ["P2P-Grouping"] = "Diagnose Peer-to-Peer Grouping service issues (group formation/security).",
            ["P2P-PNRP"] = "Diagnose Peer Name Resolution Protocol (PNRP) registration and resolution issues.",
            ["RemoteAssistance"] = "Troubleshoot Windows Remote Assistance connectivity and session setup.",
            ["Virtualization"] = "Capture networking related to virtualization (Hyper-V virtual switches, vNIC operations).",
            ["VPNServer"] = "Troubleshoot VPN server tunnel establishment, routing, authentication.",
            ["WCN"] = "Troubleshoot Windows Connect Now wireless provisioning/association.",
            ["WFP-IPsec"] = "Troubleshoot Windows Filtering Platform and IPsec negotiation/filtering.",
            ["XboxMultiplayer"] = "Troubleshoot Xbox Live Multiplayer connectivity (NAT type, session setup)."
        };

        public AdvancedNetworkingViewModel()
        {
            foreach (var kvp in ScenarioDescriptions)
            {
                var opt = new ScenarioOption { Name = kvp.Key, Description = kvp.Value };
                opt.IsSelectedChanged += ScenarioOption_IsSelectedChanged;
                _scenarioOptions.Add(opt);
            }
        }

        private void ScenarioOption_IsSelectedChanged(object? sender, EventArgs e)
        {
            UpdateProvidersForSelectedScenarios();
            OnChanged(nameof(ScenarioDescription));
            OnChanged(nameof(CanStart)); // ensure Start button re-evaluates enable state
        }

        public ObservableCollection<ScenarioOption> ScenarioOptions => _scenarioOptions;
        public ObservableCollection<NetshProviderInfoWithSelect> Providers => _providers;

        public void SetProviders(IEnumerable<NetshProviderInfoWithSelect> providers)
        {
            _providers.Clear();
            foreach (var p in providers) _providers.Add(p);
            OnChanged(nameof(Providers));
        }

        public void UpdateProvidersForSelectedScenarios()
        {
            var selected = _scenarioOptions.Where(s => s.IsSelected).Select(s => s.Name).ToList();
            if (selected.Count == 0)
            {
                // No scenarios selected -> clear provider list.
                _providers.Clear();
                OnChanged(nameof(Providers));
                return;
            }
            var union = new List<NetshProviderInfoWithSelect>();
            var seenGuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // GUID-only dedupe
            foreach (var scenario in selected)
            {
                if (StaticScenarioProviders.TryGetValue(scenario, out var providers))
                {
                    foreach (var p in providers)
                    {
                        var guidKey = p.Guid ?? string.Empty; // treat missing GUID as same bucket
                        if (seenGuids.Add(guidKey))
                        {
                            union.Add(new NetshProviderInfoWithSelect
                            {
                                Name = p.Name,
                                Guid = p.Guid,
                                DefaultLevel = p.DefaultLevel,
                                DefaultKeywords = p.DefaultKeywords
                            });
                        }
                    }
                }
            }
            SetProviders(union);
        }

        public string TraceFilePath { get => _traceFilePath; set { _traceFilePath = value; OnChanged(nameof(TraceFilePath)); OnChanged(nameof(CanStart)); } }
        public string ScenarioDescription
        {
            get
            {
                var selected = _scenarioOptions.Where(s => s.IsSelected).ToList();
                if (selected.Count == 0) return "Select one or more scenarios.";
                return string.Join("\n\n", selected.Select(s => $"{s.Name}: {s.Description}"));
            }
        }
        public string StatusLog { get => _statusLog; set { _statusLog = value; OnChanged(nameof(StatusLog)); } }
        public bool CaptureYes { get => _captureYes; set { _captureYes = value; OnChanged(nameof(CaptureYes)); } }
        public bool ReportYes { get => _reportYes; set { _reportYes = value; OnChanged(nameof(ReportYes)); } }
        public bool Overwrite { get => _overwrite; set { _overwrite = value; OnChanged(nameof(Overwrite)); } }
        public bool Persistent { get => _persistent; set { _persistent = value; OnChanged(nameof(Persistent)); } }
        public bool ProvidersMicrosoftOnly { get => _providersMicrosoftOnly; set { _providersMicrosoftOnly = value; OnChanged(nameof(ProvidersMicrosoftOnly)); } }
        public int MaxSizeMb { get => _maxSizeMb; set { _maxSizeMb = value; OnChanged(nameof(MaxSizeMb)); } }
        public int DurationSeconds { get => _durationSeconds; set { _durationSeconds = value; OnChanged(nameof(DurationSeconds)); } }
        public bool StopAfterFirewallDrop { get => _stopAfterFirewallDrop; set { _stopAfterFirewallDrop = value; OnChanged(nameof(StopAfterFirewallDrop)); } }
        public bool StopAfterFilteredDrop { get => _stopAfterFilteredDrop; set { _stopAfterFilteredDrop = value; OnChanged(nameof(StopAfterFilteredDrop)); } }
        public string? MatchSourceIp { get => _matchSourceIp; set { _matchSourceIp = value; OnChanged(nameof(MatchSourceIp)); } }
        public string? MatchDestIp { get => _matchDestIp; set { _matchDestIp = value; OnChanged(nameof(MatchDestIp)); } }
        public int? MatchSourcePort { get => _matchSourcePort; set { _matchSourcePort = value; OnChanged(nameof(MatchSourcePort)); } }
        public int? MatchDestPort { get => _matchDestPort; set { _matchDestPort = value; OnChanged(nameof(MatchDestPort)); } }

        public bool IsTracing { get => _isTracing; set { _isTracing = value; OnChanged(nameof(IsTracing)); OnChanged(nameof(CanStart)); } }
        public bool CanStart => !_isTracing && !string.IsNullOrWhiteSpace(TraceFilePath) && _scenarioOptions.Any(s => s.IsSelected);

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }
}