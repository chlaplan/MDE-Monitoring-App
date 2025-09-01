using System;
using System.Management;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class AppControlStatusService
    {
        // Win32_DeviceGuard enums: 0=Off/Disabled, 1=Enabled/Enforced, 2=Audit
        private static string Map(int? v) => v switch
        {
            1 => "Enforced",
            2 => "Audit",
            0 => "Disabled",
            _ => "Unknown"
        };

        public AppControlStatus GetStatus()
        {
            var status = new AppControlStatus();
            try
            {
                // root\Microsoft\Windows\DeviceGuard
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard", "SELECT * FROM Win32_DeviceGuard");
                foreach (ManagementObject mo in searcher.Get())
                {
                    status.KernelModeCodeIntegrity = Map(mo["CodeIntegrityPolicyEnforcementStatus"] as int?);
                    status.UserModeCodeIntegrity = Map(mo["UserModeCodeIntegrityPolicyEnforcementStatus"] as int?);
                    break;
                }
            }
            catch
            {
                // leave defaults
            }
            return status;
        }
    }
}