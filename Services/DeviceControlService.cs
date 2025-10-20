using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public static class DeviceControlService
    {
        // Local canonical directory
        private static readonly string LocalSupportDir = @"C:\ProgramData\Microsoft\Windows Defender\Support";
        private const string LogPattern = "MPDeviceControl-*.log";

        // EXISTING PUBLIC METHOD (kept for compatibility – now calls remote-aware overload)
        public static IEnumerable<DeviceControlEvent> LoadLatestDeviceControlEvents(int maxLines = 150) =>
            LoadLatestDeviceControlEvents(null, maxLines, CancellationToken.None);

        // NEW: Remote-aware overload with cancellation
        public static IEnumerable<DeviceControlEvent> LoadLatestDeviceControlEvents(
            string? targetMachine,
            int maxLines,
            CancellationToken ct)
        {
            try
            {
                ct.ThrowIfCancellationRequested();

                var (isRemote, resolvedDir, remoteDisplayHost) = ResolveDirectory(targetMachine);

                if (!Directory.Exists(resolvedDir))
                    return Error($"Device Control support directory missing: {resolvedDir}");

                // Collect a few recent logs (not just one) to cover rolling updates
                var logFiles = new DirectoryInfo(resolvedDir)
                    .GetFiles(LogPattern, SearchOption.TopDirectoryOnly)
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .Take(3)
                    .ToList();

                if (logFiles.Count == 0)
                    return Error($"No log files matching {LogPattern} in {resolvedDir}");

                var results = new List<DeviceControlEvent>(maxLines + 4);
                int parsedCount = 0;

                foreach (var file in logFiles)
                {
                    ct.ThrowIfCancellationRequested();

                    IEnumerable<string> lines;
                    try
                    {
                        // Shared read (file in use)
                        using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, detectEncodingFromByteOrderMarks: true);
                        var all = new List<string>();
                        string? line;
                        while ((line = sr.ReadLine()) != null && all.Count < 65000) // safety cap
                            all.Add(line);
                        lines = all;
                    }
                    catch (IOException)
                    {
                        // Fallback simple enumeration
                        try { lines = File.ReadLines(file.FullName); }
                        catch { continue; }
                    }

                    foreach (var line in lines)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (parsedCount >= maxLines) break;

                        if (!line.Contains("DoDevicePresenceNotification", StringComparison.OrdinalIgnoreCase))
                            continue;

                        DeviceControlEvent? parsed = null;
                        try
                        {
                            parsed = DeviceControlLogParser.ParseLine(line);
                        }
                        catch
                        {
                            // Ignore parse errors
                        }

                        if (parsed != null)
                        {
                            results.Add(parsed);
                            parsedCount++;
                        }
                    }

                    if (parsedCount >= maxLines) break;
                }

                if (results.Count == 0)
                {
                    return Error("No presence notification lines parsed (look for 'DoDevicePresenceNotification'). " +
                                 $"Directory: {resolvedDir}");
                }

                // Tag source (remote/local) as first row (informational)
                results.Insert(0, new DeviceControlEvent
                {
                    Timestamp = DateTime.Now,
                    InstancePathId = isRemote
                        ? $"Remote source: {remoteDisplayHost} ({resolvedDir}) Parsed={parsedCount}"
                        : $"Local source: {resolvedDir} Parsed={parsedCount}",
                    VID = "",
                    PID = "",
                    GrantedAccess = "",
                    DeniedAccess = ""
                });

                // Order newest first (parser sets Timestamp=DateTime.Now; prefer file order fallback)
                return results;
            }
            catch (OperationCanceledException)
            {
                return Error("Device Control enumeration canceled.");
            }
            catch (Exception ex)
            {
                return Error("Device Control read failed: " + ex.Message);
            }
        }

        // Resolve directory (local vs remote admin share)
        private static (bool IsRemote, string Directory, string DisplayHost) ResolveDirectory(string? host)
        {
            if (string.IsNullOrWhiteSpace(host) || IsLocalHost(host))
                return (false, LocalSupportDir, Environment.MachineName);

            var trimmed = host.Trim();
            var adminShare = $@"\\{trimmed}\c$\ProgramData\Microsoft\Windows Defender\Support";

            // If the remote host actually resolves locally (e.g., FQDN of self), fallback to direct path
            if (IsLocalHost(trimmed))
                return (false, LocalSupportDir, Environment.MachineName);

            return (true, adminShare, trimmed);
        }

        private static bool IsLocalHost(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return true;
            var h = value.Trim().ToLowerInvariant();
            if (h is "localhost" or "." or "127.0.0.1" or "::1") return true;

            var machine = Environment.MachineName.ToLowerInvariant();
            if (h == machine) return true;

            try
            {
                var dnsHost = Dns.GetHostName().ToLowerInvariant();
                if (h == dnsHost) return true;
                var full = Dns.GetHostEntry(dnsHost).HostName.ToLowerInvariant();
                if (h == full) return true;
            }
            catch { /* ignore */ }

            return false;
        }

        private static IEnumerable<DeviceControlEvent> Error(string msg) =>
            new[]
            {
                new DeviceControlEvent
                {
                    Timestamp = DateTime.Now,
                    InstancePathId = msg,
                    VID = "-",
                    PID = "-",
                    GrantedAccess = "-",
                    DeniedAccess = "-"
                }
            };
    }
}