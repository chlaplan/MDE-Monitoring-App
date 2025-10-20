using System;
using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using MDE_Monitoring_App.Models;
using static MDE_Monitoring_App.MainViewModel;

namespace MDE_Monitoring_App.Services
{
    public class LogCollector
    {
        private const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";

        public ObservableCollection<LogEntry> GetDefenderLogs() => GetDefenderLogs(null);

        private ObservableCollection<LogEntry> GetDefenderLogs(object? value)
        {
            throw new NotImplementedException();
        }

        // Remote-aware using EventLogSession
        public ObservableCollection<LogEntry> GetDefenderLogs(string? targetMachine, RemoteAccessOptions? remote, CancellationToken ct)
        {
            var coll = new ObservableCollection<LogEntry>();
            bool remoteMode = IsRemote(targetMachine);
            try
            {
                ct.ThrowIfCancellationRequested();
                EventLogSession session = remoteMode
                    ? (remote?.Password != null
                        ? new EventLogSession(targetMachine, remote.Domain, remote.User, remote.Password, SessionAuthentication.Default)
                        : new EventLogSession(targetMachine))
                    : EventLogSession.GlobalSession;

                var query = new EventLogQuery(DefenderChannel, PathType.LogName)
                {
                    Session = session,
                    ReverseDirection = true
                };

                using var reader = new EventLogReader(query);
                int count = 0;
                var deadline = DateTime.UtcNow + (remote?.ShortTimeout ?? TimeSpan.FromSeconds(6));

                for (EventRecord? rec = reader.ReadEvent(); rec != null && count < 400; rec = reader.ReadEvent())
                {
                    ct.ThrowIfCancellationRequested();
                    if (DateTime.UtcNow > deadline)
                    {
                        coll.Add(new LogEntry { Time = DateTime.Now, Level = "Warning", Message = "Timeout reading Defender Operational log." });
                        break;
                    }
                    try
                    {
                        coll.Add(new LogEntry
                        {
                            Time = rec.TimeCreated ?? DateTime.Now,
                            Level = MapLevel(rec.Level),
                            Message = SafeFormat(rec)
                        });
                    }
                    finally { rec.Dispose(); }
                    count++;
                }

                if (remoteMode)
                {
                    coll.Insert(0, new LogEntry
                    {
                        Time = DateTime.Now,
                        Level = "Info",
                        Message = $"Remote event log source: {targetMachine} (Cred:{(remote?.Password != null ? "Yes" : "Default")})"
                    });
                }
            }
            catch (Exception ex)
            {
                coll.Add(new LogEntry
                {
                    Time = DateTime.Now,
                    Level = "Error",
                    Message = (remoteMode ? "Remote" : "Local") + " Defender log failure: " + ex.Message
                });
            }
            return coll;
        }

        private static bool IsRemote(string? m) =>
            !string.IsNullOrWhiteSpace(m) &&
            !m.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals(".", StringComparison.OrdinalIgnoreCase);

        private static string MapLevel(byte? lvl) =>
            lvl switch
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
            try
            {
                return rec.FormatDescription() ?? "(no description)";
            }
            catch
            {
                return "(unable to format description)";
            }
        }
    }
}
