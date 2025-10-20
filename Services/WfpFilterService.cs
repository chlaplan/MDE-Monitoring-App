using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Principal;

namespace MDE_Monitoring_App.Services
{
    public enum WfpFilterCountMode
    {
        UniqueFilterIds,
        AllNameElements,
        LegacyDoubleNameHeuristic,
        PowerShellEmulation
    }

    public record WfpRuleNameCount(string Name, int Count);
    public record WfpFilterSummary
    {
        public long TotalFilterCount { get; init; }
        public long DistinctRuleNames => RuleCounts?.Count ?? 0;
        public double? FileSizeMb { get; init; }
        public string? SourceFilePath { get; init; }
        public string? ModeDiagnostics { get; init; }
        public List<WfpRuleNameCount> RuleCounts { get; init; } = new();
        public WfpFilterCountMode Mode { get; init; }
        public string? RemoteStatusNote { get; init; }
    }

    public class WfpFilterService
    {
        private readonly WfpFilterCountMode _mode;
        private readonly bool _preserveXml;
        public bool UsePsExecFallback { get; set; } = false;
        public string? PsExecCustomPath { get; set; }

        public WfpFilterService(
            WfpFilterCountMode mode = WfpFilterCountMode.UniqueFilterIds,
            bool preserveXmlForDebug = false)
        {
            _mode = mode;
            _preserveXml = preserveXmlForDebug;
        }

        // Local wrapper
        public Task<WfpFilterSummary?> GetFilterSummaryAsync(
            bool includeRuleCounts = true,
            CancellationToken ct = default) =>
            GetFilterSummaryAsync(null, includeRuleCounts, ct, TimeSpan.FromSeconds(20));

        public async Task<WfpFilterSummary?> GetFilterSummaryAsync(
            string? targetMachine,
            bool includeRuleCounts,
            CancellationToken ct,
            TimeSpan timeout)
        {
            if (IsRemote(targetMachine))
                return await GetFilterSummaryRemoteCapableAsync(targetMachine, includeRuleCounts, ct, timeout).ConfigureAwait(false);

            try
            {
                var baseDir = Path.Combine(Path.GetTempPath(), "MDEMonitor", "Wfp");
                Directory.CreateDirectory(baseDir);
                var xmlPath = Path.Combine(baseDir, $"wfp_filters_{Guid.NewGuid():N}.xml");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);

                if (!await RunNetshLocalAsync(xmlPath, cts.Token).ConfigureAwait(false))
                    return null;
                if (!File.Exists(xmlPath))
                    return null;

                var parsed = ParseByMode(xmlPath, includeRuleCounts, cts.Token);
                AttachDiagnostics(xmlPath, ref parsed, "Local");
                TryAugmentFileInfo(xmlPath, ref parsed);

                if (_preserveXml)
                    parsed = parsed with { SourceFilePath = xmlPath };
                else
                    TryDelete(xmlPath);

                return parsed;
            }
            catch { return null; }
        }

        public async Task<WfpFilterSummary?> GetFilterSummaryRemoteCapableAsync(
            string? targetMachine,
            bool includeRuleCounts,
            CancellationToken ct,
            TimeSpan timeout)
        {
            if (!IsRemote(targetMachine))
                return await GetFilterSummaryAsync(null, includeRuleCounts, ct, timeout).ConfigureAwait(false);

            var localTempDir = Path.Combine(Path.GetTempPath(), "MDEMonitor", "WfpRemote");
            Directory.CreateDirectory(localTempDir);
            var remoteFileName = $"wfp_filters_{Guid.NewGuid():N}.xml";
            var remoteTempPath = @"C:\Windows\Temp\" + remoteFileName;
            var localXmlPath = Path.Combine(localTempDir, remoteFileName);

            string execDiag;
            bool remoteOk;

            if (UsePsExecFallback)
            {
                var psExec = await RunRemoteNetshViaPsExecAsync(targetMachine!, remoteTempPath, timeout, ct).ConfigureAwait(false);
                execDiag = $"PsExecCmd={psExec.Command}; Out={psExec.StdOut}; Err={psExec.StdErr}";
                remoteOk = psExec.Success;
                if (!remoteOk)
                {
                    // fallback to PowerShell
                    remoteOk = await RunRemoteNetshAsync(targetMachine!, remoteTempPath, timeout, ct).ConfigureAwait(false);
                    execDiag += " | PsExecFail FallbackPS=" + (remoteOk ? "OK" : "FAIL");
                }
            }
            else
            {
                remoteOk = await RunRemoteNetshAsync(targetMachine!, remoteTempPath, timeout, ct).ConfigureAwait(false);
                execDiag = "PowerShellInvoke=" + (remoteOk ? "OK" : "FAIL");
            }

            if (!remoteOk)
                return FailSummary(execDiag);

            if (!TryCopyRemoteFile(remoteFileName, targetMachine!, localXmlPath))
                return FailSummary(execDiag + " | CopyFailed");

            if (!File.Exists(localXmlPath))
                return FailSummary(execDiag + " | LocalMissingAfterCopy");

            try
            {
                var parsed = ParseByMode(localXmlPath, includeRuleCounts, ct);
                AttachDiagnostics(localXmlPath, ref parsed, "Remote", execDiag);
                TryAugmentFileInfo(localXmlPath, ref parsed);
                parsed = parsed with { RemoteStatusNote = "Remote WFP enumeration succeeded." };

                if (_preserveXml)
                    parsed = parsed with { SourceFilePath = localXmlPath };
                else
                    TryDelete(localXmlPath);

                _ = Task.Run(() => TryDeleteRemoteTemp(targetMachine!, remoteTempPath));
                return parsed;
            }
            catch (Exception ex)
            {
                return FailSummary(execDiag + " | ParseError=" + ex.Message);
            }
        }

        public async Task<WfpFilterSummary> GetFilterSummarySafeAsync(
            string? targetMachine,
            bool includeRuleCounts,
            CancellationToken ct,
            TimeSpan timeout)
        {
            var summary = await GetFilterSummaryRemoteCapableAsync(targetMachine, includeRuleCounts, ct, timeout).ConfigureAwait(false)
                         ?? await GetFilterSummaryAsync(targetMachine, includeRuleCounts, ct, timeout).ConfigureAwait(false);

            return summary ?? new WfpFilterSummary
            {
                Mode = _mode,
                TotalFilterCount = 0,
                RemoteStatusNote = IsRemote(targetMachine) ? "Remote WFP enumeration failed." : "Local WFP enumeration failed.",
                ModeDiagnostics = "Enumeration returned null (netsh failure or timeout).",
                RuleCounts = includeRuleCounts ? new List<WfpRuleNameCount> { new("(No data)", 0) } : new List<WfpRuleNameCount>()
            };
        }

        private WfpFilterSummary FailSummary(string diag) =>
            new()
            {
                Mode = _mode,
                TotalFilterCount = 0,
                RemoteStatusNote = "Remote WFP failed.",
                ModeDiagnostics = diag
            };

        // Local netsh
        private async Task<bool> RunNetshLocalAsync(string xmlPath, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"wfp show filters file=\"{xmlPath}\" verbose=on",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            try
            {
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                _ = proc.StandardOutput.ReadToEndAsync();
                _ = proc.StandardError.ReadToEndAsync();
                await proc.WaitForExitAsync(ct).ConfigureAwait(false);
                return proc.ExitCode == 0 && File.Exists(xmlPath);
            }
            catch { return false; }
        }

        // Remote via PowerShell (prevent filename suffix issues)
        private async Task<bool> RunRemoteNetshAsync(string targetMachine, string remoteXmlPath, TimeSpan timeout, CancellationToken ct)
        {
            if (timeout < TimeSpan.FromSeconds(25))
                timeout = TimeSpan.FromSeconds(25);

            // Build the PowerShell script exactly like the manual example (with verbose=on and double quotes around $path in netsh)
            string scriptContent = $@"$path = '{remoteXmlPath}'
Invoke-Command -ComputerName '{EscapeSingle(targetMachine)}' -ScriptBlock {{
    param($p)
    try {{
        netsh wfp show filters file=""$p"" verbose=on | Out-Null
        if (Test-Path $p) {{ 'OK:' + $p }} else {{ 'FAIL:MissingFile' }}
    }} catch {{
        'FAIL:' + $_.Exception.Message
    }}
}} -ArgumentList $path
";

            string tempScript = Path.Combine(Path.GetTempPath(), "MDEMonitor", "WfpRemote", $"run_wfp_{Guid.NewGuid():N}.ps1");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(tempScript)!);
                await File.WriteAllTextAsync(tempScript, scriptContent, ct).ConfigureAwait(false);

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoLogo -NoProfile -ExecutionPolicy Bypass -File \"{tempScript}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return false;

                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(timeout);

                var stdOutTask = proc.StandardOutput.ReadToEndAsync();
                var stdErrTask = proc.StandardError.ReadToEndAsync();

                await proc.WaitForExitAsync(linked.Token).ConfigureAwait(false);
                var outText = (await stdOutTask.ConfigureAwait(false)).Trim();
                var errText = (await stdErrTask.ConfigureAwait(false)).Trim();

                bool okToken = outText.IndexOf("OK:", StringComparison.OrdinalIgnoreCase) >= 0;

                // UNC existence check (handles timing or localization)
                bool exists = RemoteFileExists(targetMachine, remoteXmlPath) ||
                              RemoteFileExists(targetMachine, remoteXmlPath + " verbose=on");

                // Success if OK token OR file exists
                if (!okToken && !exists && !string.IsNullOrEmpty(errText))
                    return false;

                return okToken || exists;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { File.Delete(tempScript); } catch { /* ignore */ }
            }
        }

        // Remote via PsExec
        private async Task<(bool Success, string Command, string StdOut, string StdErr)> RunRemoteNetshViaPsExecAsync(
            string targetMachine, string remoteXmlPath, TimeSpan timeout, CancellationToken ct)
        {
            var psExecPath = ResolvePsExecPath();
            if (psExecPath == null)
                return (false, "PsExec NOT FOUND", "", "");

            if (!IsProcessElevated())
                return (false, "Process not elevated", "", "");

            string primaryCmd = $"\\\\{targetMachine} -accepteula -n 10 -h -s cmd /c \"netsh wfp show filters file={remoteXmlPath}\"";
            string fallbackCmd = $"\\\\{targetMachine} -accepteula -n 10 -h -s cmd /c \"netsh wfp show filters file=\\\"{remoteXmlPath}\\\"\"";

            var primary = await ExecPsExecAsync(psExecPath, primaryCmd, timeout, ct).ConfigureAwait(false);
            if (primary.Success && RemoteFileExists(targetMachine, remoteXmlPath)) return (true, primaryCmd, primary.StdOut, primary.StdErr);

            var fallback = await ExecPsExecAsync(psExecPath, fallbackCmd, timeout, ct).ConfigureAwait(false);
            if (fallback.Success && RemoteFileExists(targetMachine, remoteXmlPath)) return (true, fallbackCmd, fallback.StdOut, fallback.StdErr);

            string combinedOut = (primary.StdOut + "\n" + fallback.StdOut).Trim();
            string combinedErr = (primary.StdErr + "\n" + fallback.StdErr).Trim();
            return (false, primaryCmd + " | " + fallbackCmd, combinedOut, combinedErr);
        }

        private string? ResolvePsExecPath()
        {
            if (!string.IsNullOrWhiteSpace(PsExecCustomPath) && File.Exists(PsExecCustomPath))
                return PsExecCustomPath;
            var baseDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            foreach (var c in new[]
            {
                Path.Combine(baseDir,"PsExec.exe"),
                @"C:\Sysinternals\PsExec.exe",
                Path.Combine(baseDir,"Tools","PsExec","PsExec.exe")
            })
                if (File.Exists(c)) return c;
            return null;
        }

        private async Task<(bool Success, string StdOut, string StdErr)> ExecPsExecAsync(
            string psExecPath, string arguments, TimeSpan timeout, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = psExecPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            try
            {
                using var proc = Process.Start(psi);
                if (proc == null) return (false, "Start failed", "");
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);
                var outTask = proc.StandardOutput.ReadToEndAsync();
                var errTask = proc.StandardError.ReadToEndAsync();
                await proc.WaitForExitAsync(cts.Token).ConfigureAwait(false);
                var stdOut = (await outTask.ConfigureAwait(false)).Trim();
                var stdErr = (await errTask.ConfigureAwait(false)).Trim();
                return (proc.ExitCode == 0, Truncate(stdOut), Truncate(stdErr));
            }
            catch (Exception ex) { return (false, $"Exception: {ex.Message}", ""); }
        }

        // File existence / copy
        private static bool RemoteFileExists(string targetMachine, string remotePath)
        {
            var fileName = Path.GetFileName(remotePath);
            var unc = $@"\\{targetMachine}\c$\Windows\Temp\{fileName}";
            var uncSuffix = unc + " verbose=on";
            return File.Exists(unc) || File.Exists(uncSuffix);
        }

        private static bool TryCopyRemoteFile(string remoteFileName, string targetMachine, string localXmlPath)
        {
            var uncBase = $@"\\{targetMachine}\c$\Windows\Temp\{remoteFileName}";
            var uncSuffix = uncBase + " verbose=on";
            try
            {
                if (File.Exists(uncBase))
                {
                    File.Copy(uncBase, localXmlPath, true);
                    return true;
                }
                if (File.Exists(uncSuffix))
                {
                    File.Copy(uncSuffix, localXmlPath, true);
                    return true;
                }
                return false;
            }
            catch { return false; }
        }

        private void TryDeleteRemoteTemp(string targetMachine, string remoteXmlPath)
        {
            // best-effort cleanup
            var cleanupScript = $@"Invoke-Command -ComputerName '{EscapeSingle(targetMachine)}' -ScriptBlock {{ try {{ if (Test-Path '{EscapeSingle(remoteXmlPath)}') {{ Remove-Item -LiteralPath '{EscapeSingle(remoteXmlPath)}' -Force -ErrorAction SilentlyContinue }} }} catch {{ }} }}";
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command " + QuoteForCmd(cleanupScript),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            try { using var proc = Process.Start(psi); proc?.WaitForExit(); } catch { }
        }

        // Parse selection
        private WfpFilterSummary ParseByMode(string path, bool includeRuleCounts, CancellationToken ct) =>
            _mode switch
            {
                WfpFilterCountMode.PowerShellEmulation => ParsePowerShellEmulation(path, includeRuleCounts, ct),
                WfpFilterCountMode.AllNameElements => ParseAllNameElements(path, includeRuleCounts, ct),
                WfpFilterCountMode.LegacyDoubleNameHeuristic => ParseLegacyDoubleName(path, includeRuleCounts, ct),
                _ => ParseUniqueFilterIds(path, includeRuleCounts, ct)
            };

        // Helpers / diagnostics
        private static void AttachDiagnostics(string xmlPath, ref WfpFilterSummary parsed, string scope, string? extra = null)
        {
            var rawFilterIdOccurrences = QuickCount(xmlPath, "<filterId>");
            var rawNameOccurrences = QuickCount(xmlPath, "<name>");
            var diag = $"{scope}; Mode={parsed.Mode}; ParsedTotal={parsed.TotalFilterCount}; Raw<filterId>={rawFilterIdOccurrences}; Raw<name>={rawNameOccurrences}; DistinctRuleNames={parsed.DistinctRuleNames}";
            if (!string.IsNullOrEmpty(extra)) diag += " | " + extra;
            parsed = parsed with { ModeDiagnostics = diag };
        }

        private static void TryAugmentFileInfo(string path, ref WfpFilterSummary summary)
        {
            try
            {
                var fi = new FileInfo(path);
                if (fi.Exists)
                    summary = summary with { FileSizeMb = fi.Length / (1024d * 1024d) };
            }
            catch { }
        }

        private static string EscapeSingle(string s) => s.Replace("'", "''");
        private static string QuoteForCmd(string s) => "\"" + s.Replace("\"", "`\"") + "\"";
        private static string Truncate(string s) => s.Length <= 600 ? s : s[..600] + "...";
        private static bool IsProcessElevated()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private static bool IsRemote(string? machine) =>
            !string.IsNullOrWhiteSpace(machine) &&
            !machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !machine.Equals(".", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(machine, Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        private static XmlReader CreateReader(string path) =>
            XmlReader.Create(File.OpenRead(path), new XmlReaderSettings
            {
                IgnoreComments = true,
                IgnoreWhitespace = true,
                DtdProcessing = DtdProcessing.Ignore
            });

        private static string SafeReadElementString(XmlReader r)
        {
            try { return r.ReadElementContentAsString(); } catch { return string.Empty; }
        }

        // Parsing implementations
        private WfpFilterSummary ParseUniqueFilterIds(string path, bool includeNames, CancellationToken ct)
        {
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;
            bool insideItem = false; string? firstName = null;
            using var reader = CreateReader(path);
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase)) { insideItem = true; firstName = null; }
                    else if (insideItem && reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                    {
                        if (firstName == null)
                        {
                            var nm = SafeReadElementString(reader).Trim();
                            if (!string.IsNullOrEmpty(nm)) firstName = nm;
                        }
                        else _ = SafeReadElementString(reader);
                    }
                    else if (insideItem && reader.Name.Equals("filterId", StringComparison.OrdinalIgnoreCase))
                    {
                        var fid = SafeReadElementString(reader).Trim();
                        if (!string.IsNullOrEmpty(fid) && ids.Add(fid) && includeNames)
                            Increment(names, firstName ?? "(Unnamed)");
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement && reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                    insideItem = false;
            }
            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.UniqueFilterIds,
                TotalFilterCount = ids.Count,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        private WfpFilterSummary ParseAllNameElements(string path, bool includeNames, CancellationToken ct)
        {
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;
            long total = 0; bool insideItem = false;
            using var reader = CreateReader(path);
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase)) insideItem = true;
                    else if (insideItem && reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                    {
                        var nm = SafeReadElementString(reader).Trim();
                        if (!string.IsNullOrEmpty(nm))
                        {
                            total++;
                            if (includeNames) Increment(names, nm);
                        }
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement && reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                    insideItem = false;
            }
            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.AllNameElements,
                TotalFilterCount = total,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        private WfpFilterSummary ParseLegacyDoubleName(string path, bool includeNames, CancellationToken ct)
        {
            long total = 0;
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;
            using var reader = CreateReader(path);
            bool insideItem = false, haveDirect = false, haveDisplay = false;

            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase)) { insideItem = true; haveDirect = false; haveDisplay = false; }
                    else if (insideItem && reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                    {
                        var nm = SafeReadElementString(reader).Trim();
                        if (!string.IsNullOrEmpty(nm))
                        {
                            if (!haveDirect && !haveDisplay)
                            {
                                haveDirect = true; total++; if (includeNames) Increment(names, nm);
                            }
                            else if (!haveDisplay)
                            {
                                haveDisplay = true; total++; if (includeNames) Increment(names, nm);
                            }
                        }
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement && reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                    insideItem = false;
            }

            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.LegacyDoubleNameHeuristic,
                TotalFilterCount = total,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        private WfpFilterSummary ParsePowerShellEmulation(string path, bool includeNames, CancellationToken ct)
        {
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;
            long total = 0;
            using var reader = CreateReader(path);
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element &&
                    reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                {
                    var nm = SafeReadElementString(reader).Trim();
                    if (!string.IsNullOrEmpty(nm))
                    {
                        total++;
                        if (includeNames) Increment(names, nm);
                    }
                }
            }
            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.PowerShellEmulation,
                TotalFilterCount = total,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        private static void Increment(Dictionary<string, int>? dict, string key)
        {
            if (dict == null) return;
            dict.TryGetValue(key, out var c);
            dict[key] = c + 1;
        }

        private static long QuickCount(string path, string token)
        {
            long count = 0;
            using var sr = new StreamReader(path);
            string? line;
            while ((line = sr.ReadLine()) != null)
                if (line.Contains(token, StringComparison.OrdinalIgnoreCase))
                    count++;
            return count;
        }

        private static List<WfpRuleNameCount> ToSorted(Dictionary<string, int> dict)
        {
            var list = new List<WfpRuleNameCount>(dict.Count);
            foreach (var kv in dict)
                list.Add(new WfpRuleNameCount(kv.Key, kv.Value));
            list.Sort((a, b) => b.Count.CompareTo(a.Count));
            return list;
        }

        private void TryDelete(string path)
        {
            try { File.Delete(path); } catch { }
        }
    }
}