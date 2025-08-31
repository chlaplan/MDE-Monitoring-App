namespace MDE_Monitoring_App.Models
{
    public class LatestDefenderVersions
    {
        public string PlatformVersion { get; set; } = string.Empty;   // AKA Antimalware client / Platform
        public string EngineVersion { get; set; } = string.Empty;
        public string SecurityIntelligenceVersion { get; set; } = string.Empty; // Definitions
        public bool IsValid =>
            !string.IsNullOrWhiteSpace(PlatformVersion) &&
            !string.IsNullOrWhiteSpace(EngineVersion) &&
            !string.IsNullOrWhiteSpace(SecurityIntelligenceVersion);
    }
}