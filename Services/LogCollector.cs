using System;
using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class LogCollector
    {
        public ObservableCollection<LogEntry> GetDefenderLogs()
        {
            var output = new ObservableCollection<LogEntry>();

            var query = new EventLogQuery(
                "Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName,
                "*[System/Provider/@Name='Microsoft-Windows-Windows Defender']"
            )
            {
                ReverseDirection = true
            };

            try
            {
                using var reader = new EventLogReader(query);
                EventRecord? rec;
                while ((rec = reader.ReadEvent()) != null)
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

                    output.Add(new LogEntry
                    {
                        Time = rec.TimeCreated ?? DateTime.Now,
                        Level = level,
                        Message = rec.FormatDescription() ?? string.Empty
                    });
                }
            }
            catch
            {
                output.Add(new LogEntry
                {
                    Time = DateTime.Now,
                    Level = "Error",
                    Message = "Failed to read Defender Operational log."
                });
            }

            return output;
        }
    }
}
