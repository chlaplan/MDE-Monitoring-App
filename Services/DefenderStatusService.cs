using MDE_Monitoring_App.Models;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Threading;

namespace MDE_Monitoring_App.Services
{
    public class DefenderStatusService
    {
        private const string RootKey   = @"SOFTWARE\Microsoft\Windows Defender";
        private const string SigKey    = RootKey + @"\Signature Updates";
        private const string EngineKey = RootKey + @"\Engine";

        // Public entry points
        public DefenderStatus GetStatus() => GetStatus(null, TimeSpan.FromSeconds(5));
        public DefenderStatus GetStatus(string? targetMachine, TimeSpan? timeout = null)
        {
            var status = new DefenderStatus();
            var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(5);

            // Try WMI first (gives richer live info). If fails, fall back to registry.
            bool local = string.IsNullOrWhiteSpace(targetMachine) ||
                         targetMachine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                         targetMachine.Equals(".", StringComparison.OrdinalIgnoreCase);

            // WMI first (populates AMRunningMode directly from class)
            if (TryPopulateFromMpComputerStatus(targetMachine, status, effectiveTimeout))
            {
                // If WMI did not return AMRunningMode for some reason, set a fallback indicator
                if (string.IsNullOrWhiteSpace(status.AMRunningMode))
                    status.AMRunningMode = local ? "Unknown (WMI)" : "Unknown (Remote WMI)";
                return status;
            }

            // Fallback registry path
            if (local)
            {
                PopulateFromLocalRegistry(status);
                if (string.IsNullOrWhiteSpace(status.AMRunningMode))
                    status.AMRunningMode = "Registry";
            }
            else
            {
                if (TryPopulateFromRemoteRegistry(targetMachine!, status))
                {
                    if (string.IsNullOrWhiteSpace(status.AMRunningMode))
                        status.AMRunningMode = "Registry (Remote)";
                }
                else
                {
                    status.AMRunningMode = "Remote read failed";
                }
            }

            // If still missing versions, make a best-effort process hint
            if (string.IsNullOrWhiteSpace(status.AMProductVersion) ||
                string.IsNullOrWhiteSpace(status.AMEngineVersion))
            {
                PopulateFromLocalProcessHints(status);
            }
            return status;
        }

        #region WMI (MSFT_MpComputerStatus)
        private bool TryPopulateFromMpComputerStatus(string? machine, DefenderStatus s, TimeSpan timeout)
        {
            try
            {
                var scopePath = string.IsNullOrWhiteSpace(machine) ||
                                machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                                machine.Equals(".", StringComparison.OrdinalIgnoreCase)
                    ? @"root\Microsoft\Windows\Defender"
                    : $@"\\{machine}\root\Microsoft\Windows\Defender";

                var scope = new ManagementScope(scopePath);
                var cts = new CancellationTokenSource(timeout);
                scope.Connect();

                var query = new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject mo in searcher.Get())
                {
                    if (cts.IsCancellationRequested) break;

                    s.AMProductVersion              = mo["AMProductVersion"]?.ToString() ?? s.AMProductVersion;
                    s.AMEngineVersion               = mo["AMEngineVersion"]?.ToString() ?? s.AMEngineVersion;
                    s.AMRunningMode                 = mo["AMRunningMode"]?.ToString() ?? s.AMRunningMode; // FIXED
                    s.RealTimeProtection            = (bool)(mo["RealTimeProtectionEnabled"] ?? false) ? "On" : "Off";

                    var avAge = mo["AntivirusSignatureAge"]?.ToString();
                    var asAge = mo["AntispywareSignatureAge"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(avAge))
                        s.AntivirusSignatureAge = avAge + " days";
                    if (!string.IsNullOrWhiteSpace(asAge))
                        s.AntispywareSignatureAge = asAge + " days";

                    s.DeviceControlDefaultEnforcement = mo["DeviceControlDefaultEnforcement"]?.ToString() ?? s.DeviceControlDefaultEnforcement;
                    s.DeviceControlState              = mo["DeviceControlState"]?.ToString() ?? s.DeviceControlState;
                    return true; // first instance sufficient
                }
            }
            catch
            {
                // Ignore – caller will fall back
            }
            return false;
        }
        #endregion

        #region Local Registry
        private void PopulateFromLocalRegistry(DefenderStatus s)
        {
            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(RootKey);
                using var sig  = Registry.LocalMachine.OpenSubKey(SigKey);
                using var eng  = Registry.LocalMachine.OpenSubKey(EngineKey);

                s.AMProductVersion = root?.GetValue("ProductVersion") as string ?? s.AMProductVersion;
                s.AMEngineVersion  = sig?.GetValue("EngineVersion") as string
                                     ?? eng?.GetValue("EngineVersion") as string
                                     ?? s.AMEngineVersion;

                var avSig = sig?.GetValue("AVSignatureVersion") as string;
                var asSig = sig?.GetValue("ASignatureVersion") as string;
                if (!string.IsNullOrWhiteSpace(avSig))
                    s.AntivirusSignatureAge = avSig;
                if (!string.IsNullOrWhiteSpace(asSig))
                    s.AntispywareSignatureAge = asSig;

                if (string.IsNullOrWhiteSpace(s.RealTimeProtection))
                    s.RealTimeProtection = GetRtStatusLocal();
            }
            catch (Exception ex)
            {
                s.RealTimeProtection = "Local registry error: " + ex.Message;
            }
        }

        private string GetRtStatusLocal()
        {
            // Lightweight local WMI attempt only for RealTimeProtection if full class failed
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender",
                    "SELECT RealTimeProtectionEnabled FROM MSFT_MpComputerStatus");
                foreach (ManagementObject mo in searcher.Get())
                {
                    return (bool)(mo["RealTimeProtectionEnabled"] ?? false) ? "On" : "Off";
                }
            }
            catch { }
            return "Unknown";
        }

        private void PopulateFromLocalProcessHints(DefenderStatus s)
        {
            // Fallback: try to read version of MsMpEng.exe if path known
            try
            {
                var sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var enginePath = Path.Combine(sysRoot, "System32", "MsMpEng.exe");
                if (File.Exists(enginePath))
                {
                    var ver = FileVersionInfo.GetVersionInfo(enginePath);
                    if (string.IsNullOrWhiteSpace(s.AMProductVersion))
                        s.AMProductVersion = ver.ProductVersion;
                    if (string.IsNullOrWhiteSpace(s.AMEngineVersion))
                        s.AMEngineVersion = ver.FileVersion;
                }
            }
            catch { }
        }
        #endregion

        #region Remote Registry
        private bool TryPopulateFromRemoteRegistry(string machine, DefenderStatus s)
        {
            try
            {
                using var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machine);
                using var root = hklm.OpenSubKey(RootKey);
                using var sig  = hklm.OpenSubKey(SigKey);
                using var eng  = hklm.OpenSubKey(EngineKey);

                s.AMProductVersion = root?.GetValue("ProductVersion") as string ?? s.AMProductVersion;
                s.AMEngineVersion  = sig?.GetValue("EngineVersion") as string
                                     ?? eng?.GetValue("EngineVersion") as string
                                     ?? s.AMEngineVersion;

                var avSig = sig?.GetValue("AVSignatureVersion") as string;
                var asSig = sig?.GetValue("ASignatureVersion") as string;
                if (!string.IsNullOrWhiteSpace(avSig))
                    s.AntivirusSignatureAge = avSig;
                if (!string.IsNullOrWhiteSpace(asSig))
                    s.AntispywareSignatureAge = asSig;

                if (string.IsNullOrWhiteSpace(s.RealTimeProtection))
                    s.RealTimeProtection = "Unknown (remote registry)";
                return true;
            }
            catch (Exception ex)
            {
                s.RealTimeProtection = "Remote registry fail: " + ex.Message;
                return false;
            }
        }
        #endregion
    }
}
