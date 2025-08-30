using System;
using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using MDEMonitor.Models;

namespace MDEMonitor.Services
{
    public class LogCollector
    {
        public ObservableCollection<LogEntry> GetDefenderLogs(int max = 400)
        {
            var logs = new ObservableCollection<LogEntry>();

            var query = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName,
                "*[System/Provider/@Name='Microsoft-Windows-Windows Defender']");
            query.ReverseDirection = true; // newest first

            using var reader = new EventLogReader(query);
            EventRecord rec;
            while ((rec = reader.ReadEvent()) != null && logs.Count < max)
            {
                var level = rec.Level switch
                {
                    1 => "Critical",
                    2 => "Error",
                    3 => "Warning",
                    4 => "Info",
                    5 => "Verbose",
                    _ => rec.LevelDisplayName ?? "Info"
                };

                logs.Add(new LogEntry
                {
                    Time = rec.TimeCreated ?? DateTime.Now,
                    Level = level,
                    Message = rec.FormatDescription() ?? string.Empty
                });
            }

            return logs;
        }
    }
}
