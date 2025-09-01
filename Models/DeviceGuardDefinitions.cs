using System;
using System.Collections.Generic;
using System.Linq;

/*
 Reference mappings (summarized from Microsoft docs):

 CodeIntegrityPolicyEnforcementStatus:
   0 = Disabled
   1 = Audit
   2 = Enforced

 VirtualizationBasedSecurityStatus:
   0 = Not Enabled
   1 = Enabled (base)
   2 = Enabled (secure / running)

 SecurityServicesConfigured / SecurityServicesRunning (uint codes):
   1 = Credential Guard
   2 = HVCI (Memory Integrity)
   3 = Secure Boot
   4 = DMA Protection
*/

namespace MDE_Monitoring_App.Models
{
    public static class DeviceGuardDefinitions
    {
        private static readonly Dictionary<uint, string> CodeIntegrityPolicyMap = new()
        {
            { 0, "Disabled" },
            { 1, "Audit" },
            { 2, "Enforced" }
        };

        private static readonly Dictionary<uint, string> VbsStatusMap = new()
        {
            { 0, "Not Enabled" },
            { 1, "Enabled (Base)" },
            { 2, "Enabled (Secure)" }
        };

        private static readonly Dictionary<uint, string> SecurityServiceMap = new()
        {
            { 1, "Credential Guard" },
            { 2, "HVCI" },
            { 3, "Secure Boot" },
            { 4, "DMA Protection" }
        };

        public static string MapCodeIntegrityPolicy(uint? value)
        {
            if (!value.HasValue) return "Unknown";
            return CodeIntegrityPolicyMap.TryGetValue(value.Value, out var name)
                ? name
                : $"Unknown ({value.Value})";
        }

        public static string MapVbsStatus(uint? value)
        {
            if (!value.HasValue) return "Unknown";
            return VbsStatusMap.TryGetValue(value.Value, out var name)
                ? name
                : $"Enabled (Code {value.Value})";
        }

        public static string MapSecurityServices(uint[]? values)
        {
            if (values == null || values.Length == 0) return "None";
            var mapped = values
                .Select(v => SecurityServiceMap.TryGetValue(v, out var n) ? n : $"Unknown({v})")
                .Distinct()
                .OrderBy(s => s)
                .ToArray();
            return string.Join(", ", mapped);
        }
    }
}