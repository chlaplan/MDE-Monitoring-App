using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MDE_Monitoring_App.Models;
using System.Threading;

namespace MDE_Monitoring_App.Services
{
    public class FirewallLogService
    {
        private const string FirewallPolicyRoot = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        private static readonly (string RegSubKey, string FriendlyName)[] ProfileKeys =
        {
            ("DomainProfile",  "Domain"),
            ("StandardProfile","Private"),
            ("PublicProfile",  "Public")
        };
        private static readonly string TempDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "MDE_Monitoring_App",
            "FirewallLogs");
        private static readonly Regex DateLineRegex = new(@"^\d{4}-\d{2}-\d{2}\s", RegexOptions.Compiled);

        public record FirewallProfileLogStatus(
            string Profile,
            string LogPath,
            bool LogDropped,
            bool LogAllowed,
            string SourceKind,     // NEW: Local/Remote
            string RawRegistryPath // NEW: original registry value
        );

        /// <summary>
        /// Remote-aware per-profile logging settings.
        /// </summary>
        public IReadOnlyList<FirewallProfileLogStatus> GetProfileStatuses(string? targetMachine = null)
        {
            bool remote = IsRemote(targetMachine);
            var list = new List<FirewallProfileLogStatus>();
            RegistryKey? root = null;
            RegistryKey? ntKey = null;
            string? remoteSystemRoot = null;

            try
            {
                root = remote
                    ? RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, targetMachine!)
                    : Registry.LocalMachine;

                if (remote)
                {
                    try
                    {
                        ntKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, targetMachine!)
                            .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                        remoteSystemRoot = ntKey?.GetValue("SystemRoot") as string; // e.g. C:\Windows
                    }
                    catch { remoteSystemRoot = null; }
                }

                foreach (var (regSubKey, friendly) in ProfileKeys)
                {
                    string loggingKeyPath = $"{FirewallPolicyRoot}\\{regSubKey}\\Logging";
                    using var key = root.OpenSubKey(loggingKeyPath);
                    if (key == null) continue;

                    string raw = (key.GetValue("LogFilePath") as string ?? "").Trim();
                    if (raw.Length == 0) continue;

                    string expanded = raw;
                    // Avoid Environment.ExpandEnvironmentVariables for remote (%SystemRoot% differs). Handle manually.
                    if (remote && remoteSystemRoot != null &&
                        expanded.IndexOf("%systemroot%", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        expanded = Regex.Replace(expanded, "%systemroot%", remoteSystemRoot, RegexOptions.IgnoreCase);
                    }
                    else
                    {
                        expanded = Environment.ExpandEnvironmentVariables(expanded); // safe for local
                    }

                    // If path lacks drive root (e.g. System32\LogFiles\Firewall\pfirewall.log) prepend remoteSystemRoot or local %SystemRoot%.
                    if (!HasDrivePrefix(expanded))
                    {
                        var baseRoot = remote
                            ? (remoteSystemRoot ?? "C:\\Windows")
                            : (Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows");
                        expanded = Path.Combine(baseRoot, expanded.TrimStart('\\'));
                    }

                    // Normalize
                    try { expanded = Path.GetFullPath(expanded); } catch { }

                    bool logDropped = (key.GetValue("LogDroppedPackets") is int d && d == 1);
                    bool logAllowed = (key.GetValue("LogSuccessfulConnections") is int a && a == 1);

                    list.Add(new FirewallProfileLogStatus(
                        friendly,
                        expanded,
                        logDropped,
                        logAllowed,
                        remote ? "Remote" : "Local",
                        raw));
                }

                // Diagnostic row if remote and no entries
                if (remote && list.Count == 0)
                {
                    list.Add(new FirewallProfileLogStatus(
                        "Diagnostic",
                        "",
                        false,
                        false,
                        "Remote",
                        "No profile logging keys found or access denied"));
                }
            }
            catch (Exception ex)
            {
                list.Add(new FirewallProfileLogStatus(
                    "Error",
                    "",
                    false,
                    false,
                    remote ? "Remote" : "Local",
                    "Exception: " + ex.Message));
            }
            finally
            {
                if (root != null && remote) root.Dispose();
                ntKey?.Dispose();
            }

            return list;
        }

        /// <summary>
        /// Remote-aware load of DROP entries. If targetMachine specified, uses UNC admin share copy (\\host\c$\...).
        /// </summary>
        public IEnumerable<FirewallLogEntry> LoadRecentDrops(int max = 300, string? targetMachine = null, CancellationToken token = default)
        {
            try
            {
                var statuses = GetProfileStatuses(targetMachine);
                var sources = statuses
                    .Where(s => s.LogDropped && !string.IsNullOrWhiteSpace(s.LogPath))
                    .Select(s => new LogSource(s.Profile, s.LogPath, s.SourceKind, s.RawRegistryPath))
                    .ToList();

                if (!sources.Any())
                    return Error(IsRemote(targetMachine)
                        ? "Remote firewall log not available or logging disabled."
                        : "No firewall log files found (dropped packet logging disabled or paths missing).");

                if (!EnsureTempDirectory(out var tempErr))
                    return Error("Failed to prepare temp directory: " + tempErr);

                var collected = new List<FirewallLogEntry>();
                foreach (var src in sources)
                {
                    token.ThrowIfCancellationRequested();

                    var resolved = ResolvePathForMachine(src.Path, targetMachine);
                    if (!File.Exists(resolved))
                    {
                        collected.AddRange(Error($"Missing file ({src.Profile}) Raw='{src.RawRegistryPath}' -> Resolved='{resolved}'"));
                        continue;
                    }

                    var tempCopy = Path.Combine(TempDir, (IsRemote(targetMachine) ? "REMOTE_" : "LOCAL_") + src.Profile + "_" + Path.GetFileName(resolved));
                    if (!TryCopy(resolved, tempCopy, out var copyErr))
                    {
                        collected.AddRange(Error($"Copy failed ({src.Profile}): {copyErr}"));
                        continue;
                    }

                    try
                    {
                        var lines = File.ReadLines(tempCopy)
                            .Select(l => l.TrimStart())
                            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#") && DateLineRegex.IsMatch(l))
                            .ToList();

                        for (int i = lines.Count - 1; i >= 0 && collected.Count < max * 4; i--)
                        {
                            var entry = ParseLine(lines[i]);
                            if (entry != null && entry.Action.Equals("DROP", StringComparison.OrdinalIgnoreCase))
                            {
                                collected.Add(entry);
                            }
                        }
                    }
                    catch (Exception exFile)
                    {
                        collected.AddRange(Error($"Read error ({src.Profile}): {exFile.Message}"));
                    }
                }

                return collected
                    .Where(e => !string.Equals(e.Action, "ERROR", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(e => e.Timestamp)
                    .Take(max)
                    .ToList();
            }
            catch (Exception ex)
            {
                return Error("Unexpected error: " + ex.Message);
            }
        }

        private sealed record LogSource(string Profile, string Path, string SourceKind, string RawRegistryPath);

        private static bool IsRemote(string? machine) =>
            !string.IsNullOrWhiteSpace(machine) &&
            !machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !machine.Equals(".", StringComparison.OrdinalIgnoreCase) &&
            !machine.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        private static bool HasDrivePrefix(string p) =>
            p.Length > 1 && p[1] == ':' && char.IsLetter(p[0]);

        // Build UNC path for remote host (supports drive-letter paths only)
        private static string ResolvePathForMachine(string originalPath, string? machine)
        {
            if (!IsRemote(machine)) return originalPath;
            if (string.IsNullOrWhiteSpace(originalPath)) return originalPath;

            // If already UNC, return as-is
            if (originalPath.StartsWith(@"\\"))
                return originalPath;

            if (HasDrivePrefix(originalPath))
            {
                var driveLetter = char.ToLowerInvariant(originalPath[0]);
                var rest = originalPath.Substring(2).TrimStart('\\');
                return $@"\\{machine}\{driveLetter}$\{rest}";
            }

            // Relative path – assume under SystemRoot
            return $@"\\{machine}\c$\{originalPath.TrimStart('\\')}";
        }

        private IEnumerable<LogSource> DiscoverEnabledDropLogFiles()
        {
            var statuses = GetProfileStatuses();
            foreach (var s in statuses)
            {
                if (s.LogDropped && !string.IsNullOrWhiteSpace(s.LogPath))
                    // UPDATED to pass SourceKind and RawRegistryPath (record now has 4 parameters)
                    yield return new LogSource(s.Profile, s.LogPath, s.SourceKind, s.RawRegistryPath);
            }
        }

        private bool EnsureTempDirectory(out string? error)
        {
            error = null;
            try
            {
                Directory.CreateDirectory(TempDir);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private bool TryCopy(string source, string dest, out string? error)
        {
            error = null;
            try
            {
                try
                {
                    File.Copy(source, dest, overwrite: true);
                    return true;
                }
                catch (IOException)
                {
                    using var src = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var dst = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None);
                    src.CopyTo(dst);
                    return true;
                }
            }
            catch (UnauthorizedAccessException uae)
            {
                error = $"Access denied: {uae.Message}";
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private FirewallLogEntry? ParseLine(string line)
        {
            var parts = Regex.Split(line.Trim(), @"\s+");
            if (parts.Length < 17) return null;

            try
            {
                var dateStr = parts[0];
                var timeStr = parts[1];
                if (!DateTime.TryParse($"{dateStr} {timeStr}", out var ts))
                    return null;

                string action = parts[2];
                string protocol = parts[3];
                string sip = parts[4];
                string dip = parts[5];
                int? sport = ToInt(parts[6]);
                int? dport = ToInt(parts[7]);
                int? size = ToInt(parts[8]);
                string info = parts[15];

                string path = string.Empty;
                int? pid = null;

                if (parts.Length == 18)
                {
                    path = parts[16];
                    pid = ToInt(parts[17]);
                }
                else
                {
                    pid = ToInt(parts[16]);
                }

                return new FirewallLogEntry
                {
                    Timestamp = ts,
                    Action = action,
                    Protocol = protocol,
                    SourceIp = sip,
                    DestinationIp = dip,
                    SourcePort = sport,
                    DestinationPort = dport,
                    Size = size,
                    Info = info,
                    Path = path,
                    Pid = pid
                };
            }
            catch
            {
                return null;
            }
        }

        private static int? ToInt(string s) => int.TryParse(s, out var v) ? v : null;

        private IEnumerable<FirewallLogEntry> Error(string message) =>
            new[]
            {
                new FirewallLogEntry
                {
                    Timestamp = DateTime.Now,
                    Action = "ERROR",
                    Protocol = "-",
                    SourceIp = "-",
                    DestinationIp = "-",
                    Info = message,
                    Path = string.Empty
                }
            };
    }
}