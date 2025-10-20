using System;
using System.Linq;
using System.Collections.Generic;

namespace MDE_Monitoring_App.Models
{
    public class DeviceGuardStatus
    {
        // Raw values from Win32_DeviceGuard
        public uint? CodeIntegrityPolicyEnforcementStatus { get; set; }
        public uint? VirtualizationBasedSecurityStatus { get; set; }
        public uint[]? SecurityServicesConfigured { get; set; }
        public uint[]? SecurityServicesRunning { get; set; }
        public uint[]? AvailableSecurityProperties { get; set; }
        public uint[]? RequiredSecurityProperties { get; set; }
        public uint[]? SecurityFeaturesEnabled { get; set; }
        public uint? UsermodeCodeIntegrityPolicyEnforcementStatus { get; set; }
        public string? InstanceIdentifier { get; set; }
        public string? Version { get; set; }

        // Enumerations (based on current Microsoft documentation)

        // SecurityServicesConfigured / SecurityServicesRunning (0..7)
        private static readonly Dictionary<uint,string> SecurityServiceNames = new()
        {
            { 1, "Credential Guard" },
            { 2, "Memory Integrity (HVCI)" },
            { 3, "System Guard Secure Launch" },
            { 4, "SMM Firmware Measurement" },
            { 5, "Kernel HW-enforced Stack Protection" },
            { 6, "Kernel HW-enforced Stack Protection (Audit)" },
            { 7, "Hypervisor-Enforced Paging Translation" }
        };

        // Available / Required Security Properties (0..8)
        private static readonly Dictionary<uint,string> SecurityPropertyNames = new()
        {
            { 0, "no relevant properties exist on the device" },
            { 1, "Hypervisor Support" },
            { 2, "Secure Boot" },
            { 3, "DMA Protection" },
            { 4, "Secure Memory Overwrite" },
            { 5, "NX Protections" },
            { 6, "SMM Mitigations" },
            { 7, "MBEC / GMET" },
            { 8, "APIC Virtualization" }
        };

        private static string MapServices(uint[]? arr)
        {
            if (arr == null || arr.Length == 0) return "None";
            var filtered = arr.Where(v => v != 0).Select(v =>
                SecurityServiceNames.TryGetValue(v, out var name) ? name : $"Unknown({v})");
            var list = string.Join(", ", filtered);
            return string.IsNullOrWhiteSpace(list) ? "None" : list;
        }

        private static string MapProperties(uint[]? arr, bool required)
        {
            if (arr == null || arr.Length == 0) return required ? "None Required" : "None Available";
            // 0 has special meaning: nothing required / no relevant properties
            if (arr.Length == 1 && arr[0] == 0)
                return required ? "None Required" : "None Available";
            var mapped = arr.Where(v => v != 0).Select(v =>
                SecurityPropertyNames.TryGetValue(v, out var name) ? name : $"Unknown({v})");
            var list = string.Join(", ", mapped);
            return string.IsNullOrWhiteSpace(list)
                ? (required ? "None Required" : "None Available")
                : list;
        }

        private static string MapFeatures(uint[]? arr)
        {
            if (arr == null || arr.Length == 0) return "None";
            // Value 0 -> None
            if (arr.Length == 1 && arr[0] == 0) return "None";
            return string.Join(", ", arr.Select(v => v == 0 ? "None" : v.ToString()));
        }

        // Displays

        public string CodeIntegrityPolicyDisplay =>
            CodeIntegrityPolicyEnforcementStatus switch
            {
                0 => "Off",
                1 => "Audit",
                2 => "Enforced",
                _ => "Unknown"
            };

        public string VbsStatusDisplay =>
            VirtualizationBasedSecurityStatus switch
            {
                0 => "VBS isn't enabled",
                1 => "VBS is enabled but not running",
                2 => "VBS is enabled and running",
                _ => "Unknown"
            };

        public string SecurityServicesConfiguredDisplay => MapServices(SecurityServicesConfigured);
        public string SecurityServicesRunningDisplay   => MapServices(SecurityServicesRunning);

        public string AvailableSecurityPropertiesDisplay => MapProperties(AvailableSecurityProperties, required: false);
        public string RequiredSecurityPropertiesDisplay  => MapProperties(RequiredSecurityProperties, required: true);
        public string SecurityFeaturesEnabledDisplay     => MapFeatures(SecurityFeaturesEnabled);

        public string UsermodeCodeIntegrityPolicyDisplay =>
            UsermodeCodeIntegrityPolicyEnforcementStatus switch
            {
                0 => "Off",
                1 => "Audit",
                2 => "Enforced",
                _ => "Unknown"
            };

        public string InstanceIdentifierDisplay => InstanceIdentifier ?? "Unknown";
        public string VersionDisplay            => Version ?? "Unknown";

        public bool HasData =>
            CodeIntegrityPolicyEnforcementStatus.HasValue ||
            VirtualizationBasedSecurityStatus.HasValue ||
            (SecurityServicesConfigured?.Length ?? 0) > 0 ||
            (SecurityServicesRunning?.Length ?? 0) > 0 ||
            (AvailableSecurityProperties?.Length ?? 0) > 0 ||
            (RequiredSecurityProperties?.Length ?? 0) > 0 ||
            (SecurityFeaturesEnabled?.Length ?? 0) > 0 ||
            UsermodeCodeIntegrityPolicyEnforcementStatus.HasValue ||
            !string.IsNullOrWhiteSpace(InstanceIdentifier) ||
            !string.IsNullOrWhiteSpace(Version);
    }
}