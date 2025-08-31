using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class FirewallLogService
    {
        private const string SourceLogPath = @"C:\Windows\System32\LogFiles\Firewall\pfirewall.log";
        private const string TempDir = @"C:\Windows\Logs";
        private static readonly string TempCopyPath = Path.Combine(TempDir, "MDE_Monitor_pfirewall.log");

        private static readonly Regex DateLineRegex = new(@"^\d{4}-\d{2}-\d{2}\s", RegexOptions.Compiled);

        public IEnumerable<FirewallLogEntry> LoadRecentDrops(int max = 300)
        {
            try
            {
                if (!File.Exists(SourceLogPath))
                    return Error("Source firewall log not found");

                if (!EnsureTempCopy(out string? copyError))
                {
                    return Error($"Failed to copy firewall log: {copyError}");
                }

                var list = new List<FirewallLogEntry>();

                // Handle lines that may have leading spaces before the date.
                var lines = File.ReadLines(TempCopyPath)
                                .Select(l => l.TrimStart())
                                .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#") && DateLineRegex.IsMatch(l))
                                .ToList();

                for (int i = lines.Count - 1; i >= 0 && list.Count < max; i--)
                {
                    var line = lines[i];
                    var entry = ParseLine(line);
                    if (entry != null && entry.Action.Equals("DROP", StringComparison.OrdinalIgnoreCase))
                        list.Add(entry);
                }

                return list
                    .OrderByDescending(e => e.Timestamp)
                    .Take(max)
                    .ToList();
            }
            catch (Exception ex)
            {
                return Error("Unexpected error: " + ex.Message);
            }
        }

        private bool EnsureTempCopy(out string? error)
        {
            error = null;
            try
            {
                if (!Directory.Exists(TempDir))
                {
                    Directory.CreateDirectory(TempDir);
                }

                try
                {
                    File.Copy(SourceLogPath, TempCopyPath, overwrite: true);
                    return true;
                }
                catch (IOException)
                {
                    try
                    {
                        using var src = new FileStream(SourceLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var dst = new FileStream(TempCopyPath, FileMode.Create, FileAccess.Write, FileShare.None);
                        src.CopyTo(dst);
                        return true;
                    }
                    catch (Exception inner)
                    {
                        error = inner.Message;
                        return false;
                    }
                }
                catch (UnauthorizedAccessException uae)
                {
                    error = $"Access denied (run elevated): {uae.Message}";
                    return false;
                }
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

                string path;
                int? pid;

                if (parts.Length == 18)
                {
                    path = parts[16];
                    pid = ToInt(parts[17]);
                }
                else
                {
                    path = string.Empty;
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
                    Info = message
                }
            };
    }
}