using System.Collections.Generic;

namespace MDE_Monitoring_App.Models
{
    public class DefenderPolicyDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Kind { get; set; } = "raw"; // raw | disableFlag | allowFlag | enum | percent | integer
        public Dictionary<string, string>? EnumMap { get; set; }
        public string? EnabledMeaning { get; set; }
        public string? DisabledMeaning { get; set; }
        public string RiskWhenDisabled { get; set; } = "Risk";
        public string DefaultSeverity { get; set; } = "Info";
    }
}