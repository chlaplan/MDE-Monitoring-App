using System;
using System.Diagnostics.Eventing.Reader;

namespace MDE_Monitoring_App.Services
{
    public class IntuneSyncService
    {
        // Event ID used to indicate end of an MDM (Intune) sync session
        private const int SyncCompletedEventId = 209;

        // Channels to probe (some systems may not have the Sync channel)
        private static readonly string[] Channels =
        {
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Sync"
        };

        /// <summary>
        /// Returns the TimeCreated (UTC) of the most recent Intune MDM sync completion event (ID 209),
        /// or null if none found or logs unavailable.
        /// </summary>
        public DateTime? GetLastSync()
        {
            DateTime? latest = null;

            foreach (var channel in Channels)
            {
                try
                {
                    // XPath: any event with EventID=209. ReverseDirection gives newest first.
                    var query = new EventLogQuery(channel, PathType.LogName, "*[System[(EventID=" + SyncCompletedEventId + ")]]")
                    {
                        ReverseDirection = true
                    };

                    using var reader = new EventLogReader(query);
                    using EventRecord? record = reader.ReadEvent(); // first (newest) match
                    if (record?.TimeCreated != null)
                    {
                        var utc = record.TimeCreated.Value.ToUniversalTime();
                        if (latest == null || utc > latest)
                            latest = utc;
                    }
                }
                catch (EventLogNotFoundException)
                {
                    // Channel might not exist on this system – ignore
                }
                catch
                {
                    // Swallow other access issues; keep trying remaining channels
                }
            }

            return latest;
        }

        /// <summary>
        /// Async wrapper for UI callers.
        /// </summary>
        public Task<DateTime?> GetLastSyncAsync() => Task.Run(GetLastSync);
    }
}