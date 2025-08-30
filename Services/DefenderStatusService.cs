using MDEMonitor.Models;
using System.Management;

namespace MDEMonitor.Services
{
    public class DefenderStatusService
    {
        public DefenderStatus GetStatus()
        {
            var status = new DefenderStatus();

            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                    "SELECT * FROM MSFT_MpComputerStatus");
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    status.AMProductVersion = queryObj["AMProductVersion"]?.ToString() ?? "Unknown";
                    status.AMEngineVersion = queryObj["AMEngineVersion"]?.ToString() ?? "Unknown";
                    status.AMRunningMode = queryObj["AMRunningMode"]?.ToString() ?? "Unknown";
                    status.RealTimeProtection = (bool)(queryObj["RealTimeProtectionEnabled"] ?? false) ? "On" : "Off";
                    status.AntivirusSignatureAge = queryObj["AntivirusSignatureAge"]?.ToString() + " days";
                    status.AntispywareSignatureAge = queryObj["AntispywareSignatureAge"]?.ToString() + " days";
                    status.DeviceControlDefaultEnforcement = queryObj["DeviceControlDefaultEnforcement"]?.ToString() ?? "Unknown";
                    status.DeviceControlState = queryObj["DeviceControlState"]?.ToString() ?? "Unknown";
                }
            }
            catch
            {
                status.AMProductVersion = "Error";
                status.AMEngineVersion = "Error";
                status.AMRunningMode = "Error";
                status.RealTimeProtection = "Error";
                status.AntivirusSignatureAge = "Error";
                status.AntispywareSignatureAge = "Error";
                status.DeviceControlDefaultEnforcement = "Error";
                status.DeviceControlState = "Error";
            }

            return status;
        }
    }
}
