using System;
using System.Linq;
using System.Management;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class DeviceGuardStatusService
    {
        public DeviceGuardStatus GetStatus()
        {
            var result = new DeviceGuardStatus();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\DeviceGuard",
                    "SELECT * FROM Win32_DeviceGuard");

                foreach (ManagementObject mo in searcher.Get())
                {
                    result.CodeIntegrityPolicyEnforcementStatus =
                        mo["CodeIntegrityPolicyEnforcementStatus"] as uint?;

                    result.VirtualizationBasedSecurityStatus =
                        mo["VirtualizationBasedSecurityStatus"] as uint?;

                    result.SecurityServicesConfigured =
                        ConvertToUIntArray(mo["SecurityServicesConfigured"]);

                    result.SecurityServicesRunning =
                        ConvertToUIntArray(mo["SecurityServicesRunning"]);

                    break;
                }
            }
            catch
            {
                // swallow; UI shows Unknown / None
            }
            return result;
        }

        private static uint[]? ConvertToUIntArray(object? raw)
        {
            if (raw == null) return null;

            try
            {
                // Direct cast succeeds if already uint[]
                if (raw is uint[] ua) return ua;

                // Some providers may return ushort[] or int[] or object[]
                if (raw is ushort[] us) return us.Select(u => (uint)u).ToArray();
                if (raw is int[] ia) return ia.Select(i => (uint)i).ToArray();
                if (raw is object[] oa)
                {
                    return oa
                        .Select(o =>
                        {
                            try { return Convert.ToUInt32(o); }
                            catch { return (uint)0xFFFFFFFF; }
                        })
                        .Where(v => v != 0xFFFFFFFF)
                        .ToArray();
                }
            }
            catch
            {
                // ignore conversion errors
            }
            return null;
        }
    }
}