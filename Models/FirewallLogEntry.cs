using System;

namespace MDE_Monitoring_App.Models
{
    public class FirewallLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Action { get; set; } = string.Empty;          // Expect "DROP" (filtered)
        public string Protocol { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;
        public int? SourcePort { get; set; }
        public int? DestinationPort { get; set; }
        public int? Size { get; set; }
        public string Info { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;            // May be blank in log
        public int? Pid { get; set; }
    }
}