using System;
using System.Collections.Generic;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    // Lightweight stub service (extend with real collection logic later)
    public static class DefenderService
    {
        public static IEnumerable<LogEntry> GetRecentMDEEvents(int maxEvents = 50)
        {
            var baseList = new List<LogEntry>
            {
                new LogEntry { Time = DateTime.Now.AddMinutes(-10), Level = "Info",    Message = "MDE running normally." },
                new LogEntry { Time = DateTime.Now.AddMinutes(-5),  Level = "Warning", Message = "Real-time scan delayed." },
                new LogEntry { Time = DateTime.Now,                 Level = "Error",   Message = "Signature update failed." }
            };
            return maxEvents < baseList.Count ? baseList.GetRange(0, maxEvents) : baseList;
        }

        public static DefenderStatus GetLiveStatus()
        {
            return new DefenderStatus
            {
                AMProductVersion = "4.18.24090.7",
                AMEngineVersion = "1.1.21200.4",
                AMRunningMode = "Normal",
                RealTimeProtection = "On",
                AntivirusSignatureAge = "2h",
                AntispywareSignatureAge = "2h",
                DeviceControlDefaultEnforcement = "Enabled",
                DeviceControlState = "Active"
            };
        }
    }
}
