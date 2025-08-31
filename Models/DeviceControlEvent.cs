using System;

namespace MDE_Monitoring_App.Models
{
    public class DeviceControlEvent
    {
        public DateTime Timestamp { get; set; }
        public string InstancePathId { get; set; } = string.Empty;
        public string VID { get; set; } = string.Empty;
        public string PID { get; set; } = string.Empty;
        public string GrantedAccess { get; set; } = string.Empty;
        public string DeniedAccess { get; set; } = string.Empty;
    }
}

