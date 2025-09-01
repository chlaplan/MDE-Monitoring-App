namespace MDE_Monitoring_App.Models
{
    public class AppControlStatus
    {
        public string KernelModeCodeIntegrity { get; set; } = "Unknown";
        public string UserModeCodeIntegrity { get; set; } = "Unknown";
    }

    public class AppControlEvent
    {
        public System.DateTime Time { get; set; }
        public int Id { get; set; }
        public string Level { get; set; } = "";
        public string Channel { get; set; } = "";
        public string Message { get; set; } = "";
    }
}