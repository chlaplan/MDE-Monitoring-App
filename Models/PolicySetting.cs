using System;

namespace MDE_Monitoring_App.Models
{
    public class PolicySetting
    {
        // Raw registry value name (or synthetic, e.g. ASRRules:{GUID})
        public string Name { get; set; } = string.Empty;

        // Friendly display name for UI
        public string DisplayName { get; set; } = string.Empty;

        // Interpreted, human-readable value
        public string InterpretedValue { get; set; } = string.Empty;

        // Original raw value (DWORD, string, etc.)
        public object? RawValue { get; set; }

        // Explanation of the policy / or preview of list items
        public string Description { get; set; } = string.Empty;

        // Info / Risk / Error etc. used for coloring
        public string Severity { get; set; } = "Info";

        // Optional source (e.g. Policy Manager, Computed, etc.)
        public string Source { get; set; } = "Policy Manager";
    }
}