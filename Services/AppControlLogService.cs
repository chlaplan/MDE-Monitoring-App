using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using MDE_Monitoring_App.Models;
using static MDE_Monitoring_App.MainViewModel;

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

        // Existing local entry point (kept for compatibility)
        public IEnumerable<AppControlEvent> GetRecent(int maxPerChannel = 100) =>
            GetRecent(null, maxPerChannel, CancellationToken.None, TimeSpan.FromSeconds(6));

        // NEW: remote-aware + timeout + cancellation
        public IEnumerable<AppControlEvent> GetRecent(
            string? targetMachine,
            int maxPerChannel,
            CancellationToken ct,
            TimeSpan timeoutPerChannel,
            RemoteAccessOptions? remote = null)
        {
            var results = new List<AppControlEvent>();
            bool remoteMode = IsRemote(targetMachine);

            foreach (var ch in Channels)
            {
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var session = remoteMode
                        ? (remote?.Password != null
                            ? new EventLogSession(targetMachine, remote.Domain, remote.User, remote.Password, SessionAuthentication.Default)
                            : new EventLogSession(targetMachine))
                        : EventLogSession.GlobalSession;

                    var query = new EventLogQuery(ch, PathType.LogName, "*[System[(Level>=0)]]")
                    {
                        ReverseDirection = true,
                        Session = session
                    };

                    using var reader = new EventLogReader(query);
                    int count = 0;
                    var deadline = DateTime.UtcNow + timeoutPerChannel;

                    for (EventRecord? rec = reader.ReadEvent();
                         rec != null && count < maxPerChannel;
                         rec = reader.ReadEvent())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (DateTime.UtcNow > deadline)
                        {
                            results.Add(new AppControlEvent
                            {
                                Time = DateTime.Now,
                                Id = -1,
                                Level = "Warning",
                                Channel = ch,
                                Message = "Timeout reading channel."
                            });
                            break;
                        }

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
                catch (Exception ex)
                {
                    results.Add(new AppControlEvent
                    {
                        Time = DateTime.Now,
                        Id = -1,
                        Level = "Error",
                        Channel = ch,
                        Message = (remoteMode ? "Remote" : "Local") + " read failed: " + ex.Message
                    });
                }
            }

            if (remoteMode)
            {
                results.Insert(0, new AppControlEvent
                {
                    Time = DateTime.Now,
                    Id = 0,
                    Level = "Info",
                    Channel = "RemoteSource",
                    Message = $"App Control events from {targetMachine} (Cred:{(remote?.Password != null ? "Yes" : "Default")})"
                });
            }

            results.Sort((a, b) => b.Time.CompareTo(a.Time));
            return results;
        }

        private static bool IsRemote(string? m) =>
            !string.IsNullOrWhiteSpace(m) &&
            !m.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !m.Equals(".", StringComparison.OrdinalIgnoreCase);

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