using System.Management;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    // WMI-based enrichment of live Defender status
    public class DefenderStatusService
    {
        public DefenderStatus GetStatus()
        {
            var status = new DefenderStatus();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender",
                    "SELECT * FROM MSFT_MpComputerStatus");

                foreach (ManagementObject mo in searcher.Get())
                {
                    status.AMProductVersion = mo["AMProductVersion"]?.ToString() ?? status.AMProductVersion;
                    status.AMEngineVersion = mo["AMEngineVersion"]?.ToString() ?? status.AMEngineVersion;
                    status.AMRunningMode = mo["AMRunningMode"]?.ToString() ?? status.AMRunningMode;
                    status.RealTimeProtection = (bool)(mo["RealTimeProtectionEnabled"] ?? false) ? "On" : "Off";
                    status.AntivirusSignatureAge = (mo["AntivirusSignatureAge"]?.ToString() ?? "0") + " days";
                    status.AntispywareSignatureAge = (mo["AntispywareSignatureAge"]?.ToString() ?? "0") + " days";
                    status.DeviceControlDefaultEnforcement = mo["DeviceControlDefaultEnforcement"]?.ToString()
                                                             ?? status.DeviceControlDefaultEnforcement;
                    status.DeviceControlState = mo["DeviceControlState"]?.ToString() ?? status.DeviceControlState;
                    break;
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
