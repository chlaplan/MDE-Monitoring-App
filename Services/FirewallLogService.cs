using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class FirewallLogService
    {
        private const string FirewallPolicyRoot = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        // Registry subkeys mapping to profiles (StandardProfile = Private)
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
            bool LogAllowed
        );

        /// <summary>
        /// Returns per-profile logging settings (path + whether dropped/allowed are logged).
        /// </summary>
        public IReadOnlyList<FirewallProfileLogStatus> GetProfileStatuses()
        {
            var list = new List<FirewallProfileLogStatus>();
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

            foreach (var (regSubKey, friendly) in ProfileKeys)
            {
                string loggingKeyPath = $"{FirewallPolicyRoot}\\{regSubKey}\\Logging";
                using var key = hklm.OpenSubKey(loggingKeyPath);
                if (key == null) continue;

                string? path = key.GetValue("LogFilePath") as string;
                if (string.IsNullOrWhiteSpace(path)) path = "";

                path = Environment.ExpandEnvironmentVariables(path.Trim());
                try { path = Path.GetFullPath(path); } catch { /* ignore */ }

                bool logDropped = (key.GetValue("LogDroppedPackets") is int d && d == 1);
                bool logAllowed = (key.GetValue("LogSuccessfulConnections") is int a && a == 1);

                list.Add(new FirewallProfileLogStatus(friendly, path, logDropped, logAllowed));
            }

            return list;
        }

        /// <summary>
        /// Loads recent DROP firewall entries from all enabled (LogDroppedPackets==true) profile logs.
        /// </summary>
        public IEnumerable<FirewallLogEntry> LoadRecentDrops(int max = 300)
        {
            try
            {
                var sources = DiscoverEnabledDropLogFiles().ToList();
                if (!sources.Any())
                    return Error("No firewall log files found (dropped packet logging disabled or paths missing).");

                if (!EnsureTempDirectory(out var tempErr))
                    return Error("Failed to prepare temp directory: " + tempErr);

                var collected = new List<FirewallLogEntry>();

                foreach (var src in sources)
                {
                    if (!File.Exists(src.Path))
                    {
                        collected.AddRange(Error($"Log file missing for profile {src.Profile}: {src.Path}"));
                        continue;
                    }

                    string tempCopy = Path.Combine(TempDir, "MDE_" + src.Profile + "_" + Path.GetFileName(src.Path));

                    if (!TryCopy(src.Path, tempCopy, out var copyErr))
                    {
                        collected.AddRange(Error($"Copy failed ({src.Profile}): {copyErr}"));
                        continue;
                    }

                    try
                    {
                        var lines = File.ReadLines(tempCopy)
                                        .Select(l => l.TrimStart())
                                        .Where(l => !string.IsNullOrWhiteSpace(l) &&
                                                    !l.StartsWith("#") &&
                                                    DateLineRegex.IsMatch(l))
                                        .ToList();

                        for (int i = lines.Count - 1; i >= 0 && collected.Count < max * 4; i--)
                        {
                            var entry = ParseLine(lines[i]);
                            if (entry != null &&
                                entry.Action.Equals("DROP", StringComparison.OrdinalIgnoreCase))
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

        private sealed record LogSource(string Profile, string Path);

        private IEnumerable<LogSource> DiscoverEnabledDropLogFiles()
        {
            var statuses = GetProfileStatuses();
            foreach (var s in statuses)
            {
                if (s.LogDropped && !string.IsNullOrWhiteSpace(s.LogPath))
                    yield return new LogSource(s.Profile, s.LogPath);
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