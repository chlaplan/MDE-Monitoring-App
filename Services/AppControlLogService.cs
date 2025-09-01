using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class AppControlLogService
    {
        private static readonly string[] Channels =
        {
            "Microsoft-Windows-CodeIntegrity/Operational",
            "Microsoft-Windows-AppLocker/MSI and Script",
            "Microsoft-Windows-AppLocker/EXE and DLL"
        };

        public IEnumerable<AppControlEvent> GetRecent(int maxPerChannel = 100)
        {
            var results = new List<AppControlEvent>();
            foreach (var ch in Channels)
            {
                try
                {
                    var query = new EventLogQuery(ch, PathType.LogName, "*[System[(Level>=0)]]")
                    {
                        ReverseDirection = true
                    };
                    using var reader = new EventLogReader(query);
                    int count = 0;
                    EventRecord? rec;
                    while (count < maxPerChannel && (rec = reader.ReadEvent()) != null)
                    {
                        using (rec)
                        {
                            results.Add(new AppControlEvent
                            {
                                Time = rec.TimeCreated?.ToLocalTime() ?? DateTime.Now,
                                Id = rec.Id,
                                Level = LevelName(rec.Level),
                                Channel = ch,
                                Message = SafeFormat(rec)
                            });
                        }
                        count++;
                    }
                }
                catch
                {
                    results.Add(new AppControlEvent
                    {
                        Time = DateTime.Now,
                        Id = -1,
                        Level = "Error",
                        Channel = ch,
                        Message = "Unable to read channel (permission or unavailable)."
                    });
                }
            }
            // Sort newest first overall
            results.Sort((a, b) => b.Time.CompareTo(a.Time));
            return results;
        }

        private static string LevelName(byte? lvl) => lvl switch
        {
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            4 => "Info",
            5 => "Verbose",
            _ => "Info"
        };

        private static string SafeFormat(EventRecord rec)
        {
            try { return (rec.FormatDescription() ?? "").Trim(); }
            catch { return "(No description)"; }
        }
    }
}