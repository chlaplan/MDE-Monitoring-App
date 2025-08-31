using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public static class DeviceControlService
    {
        private static readonly string SupportDir = @"C:\ProgramData\Microsoft\Windows Defender\Support";

        public static IEnumerable<DeviceControlEvent> LoadLatestDeviceControlEvents(int maxLines = 50)
        {
            var list = new List<DeviceControlEvent>();
            try
            {
                if (!Directory.Exists(SupportDir)) return list;

                var latestLog = new DirectoryInfo(SupportDir)
                    .GetFiles("MPDeviceControl-*.log")
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .FirstOrDefault();

                if (latestLog == null) return list;

                using var fs = new FileStream(latestLog.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (!line.Contains("DoDevicePresenceNotification"))
                        continue;

                    var parsed = DeviceControlLogParser.ParseLine(line);
                    if (parsed != null) list.Add(parsed);
                }
            }
            catch
            {
                list.Add(new DeviceControlEvent
                {
                    Timestamp = DateTime.Now,
                    InstancePathId = "Error reading log"
                });
            }

            return list
                .OrderByDescending(e => e.Timestamp)
                .Take(maxLines)
                .ToList();
        }
    }
}
