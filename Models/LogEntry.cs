using System;

namespace MDE_Monitoring_App.Models
{
    public class LogEntry
    {
        public DateTime Time { get; set; }
        public string Level { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }
}

