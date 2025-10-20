using System;

namespace MDE_Monitoring_App.Models
{
    public class IntuneEnrollmentInfo
    {
        public string Type { get; set; } = "Unknown";              // Intune / ConfigMgr / Co-managed / Unknown (raw assigned)
        public string UPN { get; set; } = "Unknown";
        public string CurKeyContainer { get; set; } = "Unknown";

        public int? EnrollmentStateRaw { get; set; }

        // Derive co-management when CurKeyContainer == "ConfigMgr"
        public bool IsCoManaged => CurKeyContainer == "ConfigMgr";

        // Effective (derived) type honoring co-management rule.
        public string EffectiveType => IsCoManaged ? "Co-managed" : Type;

        // Enrollment origin description.
        public string EnrollmentOrigin => IsCoManaged
            ? "Enrolled to Intune via ConfigMgr (Co-managed)"
            : (Type == "Intune" ? "Native Intune Enrollment" : Type);

        public string EnrollmentStateDisplay
        {
            get
            {
                string baseState = EnrollmentStateRaw switch
                {
                    0 => "None / Not Enrolled",
                    1 => "Enrolled",
                    2 => "Pending",
                    3 => "Failed",
                    _ => EnrollmentStateRaw.HasValue ? $"State {EnrollmentStateRaw}" : "Unknown"
                };

                if (IsCoManaged && baseState.StartsWith("Enrolled", StringComparison.OrdinalIgnoreCase))
                    baseState += " (Co-managed via ConfigMgr)";

                return baseState;
            }
        }

        public bool HasData =>
            CurKeyContainer is not "Unknown" || UPN is not "Unknown" || EnrollmentStateRaw.HasValue;
    }
}