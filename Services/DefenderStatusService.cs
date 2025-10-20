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
        private const string RootKey     = @"SOFTWARE\Microsoft\Windows Defender";
        private const string SigKey      = RootKey + @"\Signature Updates";
        private const string EngineKey   = RootKey + @"\Engine";
        private const string FeaturesKey = RootKey + @"\Features"; 

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

                // WMI block (insert before 'return true;'):
                if (string.IsNullOrWhiteSpace(status.DeviceControlDefaultEnforcement))
                    status.DeviceControlDefaultEnforcement = string.Empty;

                // Add this to ensure post‑WMI registry fallback if needed:
                if (status.IsTamperProtected == null)
                {
                    status.IsTamperProtected = local ? ReadTamperProtectionLocal()
                                                     : (targetMachine != null ? ReadTamperProtectionRemote(targetMachine) : null);
                }

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

                var scope = new ManagementScope(scopePath, new ConnectionOptions
                {
                    Impersonation = ImpersonationLevel.Impersonate,
                    EnablePrivileges = true
                });
                scope.Connect();

                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus"));
                foreach (ManagementObject mo in searcher.Get())
                {
                    s.AMProductVersion  = mo["AMProductVersion"]?.ToString() ?? s.AMProductVersion;
                    s.AMEngineVersion   = mo["AMEngineVersion"]?.ToString() ?? s.AMEngineVersion;
                    s.AMRunningMode     = mo["AMRunningMode"]?.ToString() ?? s.AMRunningMode;
                    s.RealTimeProtection= (bool)(mo["RealTimeProtectionEnabled"] ?? false) ? "On" : "Off";

                    var avAge = mo["AntivirusSignatureAge"]?.ToString();
                    var asAge = mo["AntispywareSignatureAge"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(avAge)) s.AntivirusSignatureAge = avAge + " days";
                    if (!string.IsNullOrWhiteSpace(asAge)) s.AntispywareSignatureAge = asAge + " days";

                    s.DeviceControlDefaultEnforcement = mo["DeviceControlDefaultEnforcement"]?.ToString() ?? s.DeviceControlDefaultEnforcement;
                    s.DeviceControlState              = mo["DeviceControlState"]?.ToString() ?? s.DeviceControlState;

                    // Simplified tamper property handling (covers bool / numeric / string)
                    try
                    {
                        var raw = mo["IsTamperProtected"];
                        if (raw is bool b) s.IsTamperProtected = b;
                        else if (raw is int i) s.IsTamperProtected = i != 0;
                        else if (raw is uint u) s.IsTamperProtected = u != 0;
                        else if (bool.TryParse(raw?.ToString(), out var b2)) s.IsTamperProtected = b2;
                        else if (int.TryParse(raw?.ToString(), out var i2)) s.IsTamperProtected = i2 != 0;
                    }
                    catch { }

                    if (string.IsNullOrWhiteSpace(s.DeviceControlDefaultEnforcement))
                        s.DeviceControlDefaultEnforcement = string.Empty;

                    // Registry fallback for tamper protection if WMI didn't populate
                    if (!s.IsTamperProtected.HasValue)
                    {
                        var local = string.IsNullOrWhiteSpace(machine) ||
                                    machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                                    machine.Equals(".", StringComparison.OrdinalIgnoreCase);
                        s.IsTamperProtected = local ? ReadTamperProtectionLocal()
                                                    : (machine != null ? ReadTamperProtectionRemote(machine) : null);
                    }

                    // PowerShell fallback if still unknown
                    if (!s.IsTamperProtected.HasValue)
                        s.IsTamperProtected = TryGetTamperProtectionViaPowerShell(machine, timeout);

                    return true;
                }
            }
            catch
            {
                // ignore
            }
            return false;
        }

        private bool? TryGetTamperProtectionViaPowerShell(string? machine, TimeSpan timeout)
        {
            try
            {
                var targetPart = string.IsNullOrWhiteSpace(machine) ? "" : $"-ComputerName '{machine}'";
                // Get-MpComputerStatus is local only; remote requires Invoke-Command
                var script = string.IsNullOrWhiteSpace(machine)
                    ? "(Get-MpComputerStatus).IsTamperProtected"
                    : $"Invoke-Command {targetPart} -ScriptBlock {{ (Get-MpComputerStatus).IsTamperProtected }}";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command " + "\"" + script.Replace("\"", "`\"") + "\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return null;

                if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
                {
                    try { proc.Kill(); } catch { }
                    return null;
                }

                var output = proc.StandardOutput.ReadToEnd().Trim();
                if (bool.TryParse(output, out var b)) return b;
                if (int.TryParse(output, out var i)) return i != 0;
                return null;
            }
            catch { return null; }
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
                using var feat = Registry.LocalMachine.OpenSubKey(FeaturesKey); // NEW

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

                if (!s.IsTamperProtected.HasValue && feat != null)
                {
                    var tp = feat.GetValue("TamperProtection");
                    if (tp is int i)
                        s.IsTamperProtected = i != 0;
                    else if (tp is string str && int.TryParse(str, out var parsed))
                        s.IsTamperProtected = parsed != 0;
                }

                // In PopulateFromLocalRegistry (end of try, before catch):
                if (string.IsNullOrWhiteSpace(s.DeviceControlDefaultEnforcement))
                    s.DeviceControlDefaultEnforcement = string.Empty;
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
                using var feat = hklm.OpenSubKey(FeaturesKey);

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

                if (!s.IsTamperProtected.HasValue && feat != null)
                {
                    var tp = feat.GetValue("TamperProtection");
                    if (tp is int i)
                        s.IsTamperProtected = i != 0;
                    else if (tp is string str && int.TryParse(str, out var parsed))
                        s.IsTamperProtected = parsed != 0;
                }

                // In TryPopulateFromRemoteRegistry (before 'return true;'):
                if (string.IsNullOrWhiteSpace(s.DeviceControlDefaultEnforcement))
                    s.DeviceControlDefaultEnforcement = string.Empty;

                return true;
            }
            catch (Exception ex)
            {
                s.RealTimeProtection = "Remote registry fail: " + ex.Message;
                return false;
            }
        }
        #endregion

        // Add these helper methods inside DefenderStatusService (e.g. below existing region blocks)
        private bool? ReadTamperProtectionLocal()
        {
            try
            {
                using var feat = Registry.LocalMachine.OpenSubKey(FeaturesKey);
                var tp = feat?.GetValue("TamperProtection");
                if (tp is int i) return i != 0;
                if (tp is uint u) return u != 0;
                if (tp is string s && int.TryParse(s, out var parsed)) return parsed != 0;
            }
            catch { }
            return null;
        }

        private bool? ReadTamperProtectionRemote(string machine)
        {
            try
            {
                using var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machine);
                using var feat = hklm.OpenSubKey(FeaturesKey);
                var tp = feat?.GetValue("TamperProtection");
                if (tp is int i) return i != 0;
                if (tp is uint u) return u != 0;
                if (tp is string s && int.TryParse(s, out var parsed)) return parsed != 0;
            }
            catch { }
            return null;
        }
    }
}
