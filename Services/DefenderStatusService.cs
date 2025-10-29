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
        private const string WDBase = @"SOFTWARE\Microsoft\Windows Defender";
        private const string WDSpynet = WDBase + @"\Spynet";
        private const string WDRealTime = WDBase + @"\Real-Time Protection";
        private const string CI_SAC_Key = @"SYSTEM\CurrentControlSet\Control\CI\Policy";

        // Public entry points
        public DefenderStatus GetStatus() => GetStatus(null, TimeSpan.FromSeconds(5));
        public DefenderStatus GetStatus(string? targetMachine, TimeSpan? timeout = null)
        {
            var status = new DefenderStatus();
            var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(5);

            bool local = string.IsNullOrWhiteSpace(targetMachine) ||
                         targetMachine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                         targetMachine.Equals(".", StringComparison.OrdinalIgnoreCase);

            if (TryPopulateFromMpComputerStatus(targetMachine, status, effectiveTimeout))
            {
                if (string.IsNullOrWhiteSpace(status.AMRunningMode))
                    status.AMRunningMode = local ? "Unknown (WMI)" : "Unknown (Remote WMI)";

                if (string.IsNullOrWhiteSpace(status.DeviceControlDefaultEnforcement))
                    status.DeviceControlDefaultEnforcement = string.Empty;

                if (status.IsTamperProtected == null)
                {
                    status.IsTamperProtected = local ? ReadTamperProtectionLocal()
                                                     : (targetMachine != null ? ReadTamperProtectionRemote(targetMachine) : null);
                }

                // NEW: supplement values (Cloud/Sample/IOAV/OnAccess/SAC) via registry when WMI succeeded
                SupplementFromRegistry(status, targetMachine);
                return status;
            }

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

                    // New: scan ages
                    if (int.TryParse(mo["QuickScanAge"]?.ToString(), out var qAge)) s.QuickScanAgeDays = qAge;
                    if (int.TryParse(mo["FullScanAge"]?.ToString(), out var fAge))  s.FullScanAgeDays  = fAge;

                    // New: IOAV / On-access / Smart App Control via WMI properties
                    if (mo["IoavProtectionEnabled"] is bool ioavBool)
                        s.IoavProtection = ioavBool ? "On" : "Off";
                    if (mo["OnAccessProtectionEnabled"] is bool onAccBool)
                        s.OnAccessProtection = onAccBool ? "On" : "Off";
                    var sacStateObj = mo["SmartAppControlState"];
                    if (sacStateObj != null && int.TryParse(sacStateObj.ToString(), out var sacState))
                        s.SmartAppControl = sacState == 2 ? "On" : sacState == 1 ? "Eval" : sacState == 0 ? "Off" : "Unknown";

                    // Simplified tamper property handling
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

                    if (!s.IsTamperProtected.HasValue)
                    {
                        var local = string.IsNullOrWhiteSpace(machine) ||
                                    machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                                    machine.Equals(".", StringComparison.OrdinalIgnoreCase);
                        s.IsTamperProtected = local ? ReadTamperProtectionLocal()
                                                    : (machine != null ? ReadTamperProtectionRemote(machine) : null);
                    }

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
                using var feat = Registry.LocalMachine.OpenSubKey(FeaturesKey);

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

                if (string.IsNullOrWhiteSpace(s.DeviceControlDefaultEnforcement))
                    s.DeviceControlDefaultEnforcement = string.Empty;

                using var sp = Registry.LocalMachine.OpenSubKey(WDSpynet);
                if (sp != null)
                {
                    int maps = Convert.ToInt32(sp.GetValue("SpyNetReporting", 0));
                    s.CloudProtection = maps > 0 ? "On" : "Off";
                    int submit = Convert.ToInt32(sp.GetValue("SubmitSamplesConsent", 0));
                    s.SampleSubmission = (submit == 1 || submit == 3) ? "On" : "Off";
                }

                using var rt = Registry.LocalMachine.OpenSubKey(WDRealTime);
                if (rt != null)
                {
                    int ioavDis = Convert.ToInt32(rt.GetValue("DisableIOAVProtection", 0));
                    s.IoavProtection = ioavDis == 0 ? "On" : "Off";
                    int onAccessDis = Convert.ToInt32(rt.GetValue("DisableOnAccessProtection", 0));
                    s.OnAccessProtection = onAccessDis == 0 ? "On" : "Off";
                }

                using var sac = Registry.LocalMachine.OpenSubKey(CI_SAC_Key);
                if (sac != null)
                {
                    int state = Convert.ToInt32(sac.GetValue("VerifiedAndReputablePolicyState", -1));
                    s.SmartAppControl = state == 2 ? "On" : state == 1 ? "Eval" : state == 0 ? "Off" : "Unknown";
                }
            }
            catch (Exception ex)
            {
                s.RealTimeProtection = "Local registry error: " + ex.Message;
            }
        }

        private string GetRtStatusLocal()
        {
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

                using (var sp = hklm.OpenSubKey(WDSpynet))
                {
                    if (sp != null)
                    {
                        int maps = Convert.ToInt32(sp.GetValue("SpyNetReporting", 0));
                        s.CloudProtection = maps > 0 ? "On" : "Off";
                        int submit = Convert.ToInt32(sp.GetValue("SubmitSamplesConsent", 0));
                        s.SampleSubmission = (submit == 1 || submit == 3) ? "On" : "Off";
                    }
                }

                using (var rt = hklm.OpenSubKey(WDRealTime))
                {
                    if (rt != null)
                    {
                        int ioavDis = Convert.ToInt32(rt.GetValue("DisableIOAVProtection", 0));
                        s.IoavProtection = ioavDis == 0 ? "On" : "Off";
                        int onAccessDis = Convert.ToInt32(rt.GetValue("DisableOnAccessProtection", 0));
                        s.OnAccessProtection = onAccessDis == 0 ? "On" : "Off";
                    }
                }

                using (var sac = hklm.OpenSubKey(CI_SAC_Key))
                {
                    if (sac != null)
                    {
                        int state = Convert.ToInt32(sac.GetValue("VerifiedAndReputablePolicyState", -1));
                        s.SmartAppControl = state == 2 ? "On" : state == 1 ? "Eval" : state == 0 ? "Off" : "Unknown";
                    }
                }

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

        // NEW: Supplement after WMI success
        private void SupplementFromRegistry(DefenderStatus s, string? machine)
        {
            try
            {
                bool local = string.IsNullOrWhiteSpace(machine) ||
                             machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                             machine.Equals(".", StringComparison.OrdinalIgnoreCase);

                if (local)
                {
                    using var sp = Registry.LocalMachine.OpenSubKey(WDSpynet);
                    if (sp != null)
                    {
                        if (string.IsNullOrWhiteSpace(s.CloudProtection))
                        {
                            int maps = Convert.ToInt32(sp.GetValue("SpyNetReporting", 0));
                            s.CloudProtection = maps > 0 ? "On" : "Off";
                        }
                        if (string.IsNullOrWhiteSpace(s.SampleSubmission))
                        {
                            int submit = Convert.ToInt32(sp.GetValue("SubmitSamplesConsent", 0));
                            s.SampleSubmission = (submit == 1 || submit == 3) ? "On" : "Off";
                        }
                    }
                    using var rt = Registry.LocalMachine.OpenSubKey(WDRealTime);
                    if (rt != null)
                    {
                        if (string.IsNullOrWhiteSpace(s.IoavProtection))
                        {
                            int ioavDis = Convert.ToInt32(rt.GetValue("DisableIOAVProtection", 0));
                            s.IoavProtection = ioavDis == 0 ? "On" : "Off";
                        }
                        if (string.IsNullOrWhiteSpace(s.OnAccessProtection))
                        {
                            int onAccessDis = Convert.ToInt32(rt.GetValue("DisableOnAccessProtection", 0));
                            s.OnAccessProtection = onAccessDis == 0 ? "On" : "Off";
                        }
                    }
                    using var sac = Registry.LocalMachine.OpenSubKey(CI_SAC_Key);
                    if (sac != null && string.IsNullOrWhiteSpace(s.SmartAppControl))
                    {
                        int state = Convert.ToInt32(sac.GetValue("VerifiedAndReputablePolicyState", -1));
                        s.SmartAppControl = state == 2 ? "On" : state == 1 ? "Eval" : state == 0 ? "Off" : "Unknown";
                    }
                }
                else
                {
                    using var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, machine!);
                    using var sp = hklm.OpenSubKey(WDSpynet);
                    if (sp != null)
                    {
                        if (string.IsNullOrWhiteSpace(s.CloudProtection))
                        {
                            int maps = Convert.ToInt32(sp.GetValue("SpyNetReporting", 0));
                            s.CloudProtection = maps > 0 ? "On" : "Off";
                        }
                        if (string.IsNullOrWhiteSpace(s.SampleSubmission))
                        {
                            int submit = Convert.ToInt32(sp.GetValue("SubmitSamplesConsent", 0));
                            s.SampleSubmission = (submit == 1 || submit == 3) ? "On" : "Off";
                        }
                    }
                    using var rt = hklm.OpenSubKey(WDRealTime);
                    if (rt != null)
                    {
                        if (string.IsNullOrWhiteSpace(s.IoavProtection))
                        {
                            int ioavDis = Convert.ToInt32(rt.GetValue("DisableIOAVProtection", 0));
                            s.IoavProtection = ioavDis == 0 ? "On" : "Off";
                        }
                        if (string.IsNullOrWhiteSpace(s.OnAccessProtection))
                        {
                            int onAccessDis = Convert.ToInt32(rt.GetValue("DisableOnAccessProtection", 0));
                            s.OnAccessProtection = onAccessDis == 0 ? "On" : "Off";
                        }
                    }
                    using var sac = hklm.OpenSubKey(CI_SAC_Key);
                    if (sac != null && string.IsNullOrWhiteSpace(s.SmartAppControl))
                    {
                        int state = Convert.ToInt32(sac.GetValue("VerifiedAndReputablePolicyState", -1));
                        s.SmartAppControl = state == 2 ? "On" : state == 1 ? "Eval" : state == 0 ? "Off" : "Unknown";
                    }
                }
            }
            catch
            {
                // ignore supplemental failures
            }
        }

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
