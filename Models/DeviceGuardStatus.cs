using System;
using System.Linq;

namespace MDE_Monitoring_App.Models
{
    public class DeviceGuardStatus
    {
        // Raw values
        public uint? CodeIntegrityPolicyEnforcementStatus { get; set; }
        public uint? VirtualizationBasedSecurityStatus { get; set; }
        public uint[]? SecurityServicesConfigured { get; set; }
        public uint[]? SecurityServicesRunning { get; set; }

        // Friendly display strings
        public string CodeIntegrityPolicyDisplay =>
            DeviceGuardDefinitions.MapCodeIntegrityPolicy(CodeIntegrityPolicyEnforcementStatus);

        public string VbsStatusDisplay =>
            DeviceGuardDefinitions.MapVbsStatus(VirtualizationBasedSecurityStatus);

        public string SecurityServicesConfiguredDisplay =>
            DeviceGuardDefinitions.MapSecurityServices(SecurityServicesConfigured);

        public string SecurityServicesRunningDisplay =>
            DeviceGuardDefinitions.MapSecurityServices(SecurityServicesRunning);

        public bool HasData =>
            CodeIntegrityPolicyEnforcementStatus.HasValue ||
            VirtualizationBasedSecurityStatus.HasValue ||
            (SecurityServicesConfigured?.Length ?? 0) > 0 ||
            (SecurityServicesRunning?.Length ?? 0) > 0;
    }
}