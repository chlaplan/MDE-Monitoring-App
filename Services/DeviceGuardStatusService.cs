using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class DeviceGuardStatusService
    {
        public bool UsePsExecFallback { get; set; }
        public string? PsExecCustomPath { get; set; }

        // Local only (legacy)
        public DeviceGuardStatus GetStatus() => GetStatusInternal(null);

        // Local or remote (sync)
        public DeviceGuardStatus GetStatus(string? targetMachine) =>
            GetStatusInternal(IsRemote(targetMachine) ? targetMachine : null);

        // Async (WMI -> PowerShell -> PsExec)
        public async Task<DeviceGuardStatus> GetStatusAsync(string? targetMachine, TimeSpan timeout, CancellationToken ct)
        {
            targetMachine = IsRemote(targetMachine) ? targetMachine : null;

            // WMI
            DeviceGuardStatus? wmiStatus;
            if (TryGetViaWmi(targetMachine, out wmiStatus) && wmiStatus != null)
                return Mark(wmiStatus);

            // PowerShell remoting
            if (targetMachine != null)
            {
                var psStatus = await TryGetViaPowerShellAsync(targetMachine, timeout, ct).ConfigureAwait(false);
                if (psStatus != null) return Mark(psStatus);
            }

            // PsExec fallback
            if (targetMachine != null && UsePsExecFallback)
            {
                var peStatus = await TryGetViaPsExecAsync(targetMachine, timeout, ct).ConfigureAwait(false);
                if (peStatus != null) return Mark(peStatus);
            }

            return targetMachine == null ? Mark(GetStatusInternal(null)) : new DeviceGuardStatus();
        }

        // Internal local retrieval
        private DeviceGuardStatus GetStatusInternal(string? remoteMachine)
        {
            if (!TryGetViaWmi(remoteMachine, out var status) || status == null)
                return new DeviceGuardStatus();
            return Mark(status);
        }

        // WMI (no Timeout property used – ConnectionOptions.Timeout does not exist in System.Management)
        private bool TryGetViaWmi(string? remoteMachine, out DeviceGuardStatus? status)
        {
            status = null;
            try
            {
                var scope = remoteMachine == null
                    ? new ManagementScope(@"root\Microsoft\Windows\DeviceGuard")
                    : new ManagementScope($@"\\{remoteMachine}\root\Microsoft\Windows\DeviceGuard",
                        new ConnectionOptions
                        {
                            Impersonation = ImpersonationLevel.Impersonate,
                            EnablePrivileges = true
                        });

                scope.Connect();
                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_DeviceGuard"));
                foreach (ManagementObject mo in searcher.Get())
                {
                    status = new DeviceGuardStatus
                    {
                        CodeIntegrityPolicyEnforcementStatus = mo["CodeIntegrityPolicyEnforcementStatus"] as uint?,
                        VirtualizationBasedSecurityStatus    = mo["VirtualizationBasedSecurityStatus"] as uint?,
                        SecurityServicesConfigured           = ConvertToUIntArray(mo["SecurityServicesConfigured"]),
                        SecurityServicesRunning              = ConvertToUIntArray(mo["SecurityServicesRunning"]),
                        AvailableSecurityProperties          = ConvertToUIntArray(mo["AvailableSecurityProperties"]),
                        RequiredSecurityProperties           = ConvertToUIntArray(mo["RequiredSecurityProperties"]),
                        SecurityFeaturesEnabled              = ConvertToUIntArray(mo["SecurityFeaturesEnabled"]),
                        UsermodeCodeIntegrityPolicyEnforcementStatus = mo["UsermodeCodeIntegrityPolicyEnforcementStatus"] as uint?,
                        InstanceIdentifier                   = mo["InstanceIdentifier"] as string,
                        Version                              = mo["Version"] as string
                    };
                    break;
                }
                return status != null;
            }
            catch
            {
                return false;
            }
        }

        // PowerShell remoting async
        private async Task<DeviceGuardStatus?> TryGetViaPowerShellAsync(string remoteMachine, TimeSpan timeout, CancellationToken ct)
        {
            try
            {
                var script = $@"Invoke-Command -ComputerName '{Escape(remoteMachine)}' -ScriptBlock {{
    try {{
        $d = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard |
              Select-Object -First 1 CodeIntegrityPolicyEnforcementStatus,VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,AvailableSecurityProperties,RequiredSecurityProperties,SecurityFeaturesEnabled,UsermodeCodeIntegrityPolicyEnforcementStatus,InstanceIdentifier,Version
        if ($d) {{ $d | ConvertTo-Json -Compress }} else {{ '{{}}' }}
    }} catch {{ '{{}}' }}
}}";

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command " + QuoteForCmd(script),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return null;

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);

                var readTask = proc.StandardOutput.ReadToEndAsync();
                var errTask = proc.StandardError.ReadToEndAsync();

                await Task.WhenAny(Task.Delay(timeout, cts.Token), proc.WaitForExitAsync(cts.Token)).ConfigureAwait(false);
                if (!proc.HasExited)
                {
                    try { proc.Kill(); } catch { }
                    return null;
                }

                var json = (await readTask.ConfigureAwait(false)).Trim();
                if (string.IsNullOrWhiteSpace(json) || json == "{}") return null;

                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                return new DeviceGuardStatus
                {
                    CodeIntegrityPolicyEnforcementStatus = TryGetUInt(root, "CodeIntegrityPolicyEnforcementStatus"),
                    VirtualizationBasedSecurityStatus    = TryGetUInt(root, "VirtualizationBasedSecurityStatus"),
                    SecurityServicesConfigured           = TryGetUIntArray(root, "SecurityServicesConfigured"),
                    SecurityServicesRunning              = TryGetUIntArray(root, "SecurityServicesRunning"),
                    AvailableSecurityProperties          = TryGetUIntArray(root, "AvailableSecurityProperties"),
                    RequiredSecurityProperties           = TryGetUIntArray(root, "RequiredSecurityProperties"),
                    SecurityFeaturesEnabled              = TryGetUIntArray(root, "SecurityFeaturesEnabled"),
                    UsermodeCodeIntegrityPolicyEnforcementStatus = TryGetUInt(root, "UsermodeCodeIntegrityPolicyEnforcementStatus"),
                    InstanceIdentifier                   = TryGetString(root, "InstanceIdentifier"),
                    Version                              = TryGetString(root, "Version")
                };
            }
            catch
            {
                return null;
            }
        }

        // PsExec async
        private async Task<DeviceGuardStatus?> TryGetViaPsExecAsync(string remoteMachine, TimeSpan timeout, CancellationToken ct)
        {
            var psExecPath = ResolvePsExecPath();
            if (psExecPath == null) return null;

            var inner = "powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command " +
                        "\"$d=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -Class Win32_DeviceGuard|" +
                        "Select -First 1 CodeIntegrityPolicyEnforcementStatus,VirtualizationBasedSecurityStatus," +
                        "SecurityServicesConfigured,SecurityServicesRunning,AvailableSecurityProperties,RequiredSecurityProperties,SecurityFeaturesEnabled,UsermodeCodeIntegrityPolicyEnforcementStatus,InstanceIdentifier,Version; if($d){$d|ConvertTo-Json -Compress}else{'{}'}\"";

            var arguments = $@"\\{remoteMachine} -accepteula -n 10 -h -s cmd /c {inner}";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = psExecPath,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return null;

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);

                var readTask = proc.StandardOutput.ReadToEndAsync();
                var errTask = proc.StandardError.ReadToEndAsync();

                await Task.WhenAny(Task.Delay(timeout, cts.Token), proc.WaitForExitAsync(cts.Token)).ConfigureAwait(false);
                if (!proc.HasExited)
                {
                    try { proc.Kill(); } catch { }
                    return null;
                }
                if (proc.ExitCode != 0) return null;

                var json = (await readTask.ConfigureAwait(false)).Trim();
                if (string.IsNullOrWhiteSpace(json) || json == "{}") return null;

                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                return new DeviceGuardStatus
                {
                    CodeIntegrityPolicyEnforcementStatus = TryGetUInt(root, "CodeIntegrityPolicyEnforcementStatus"),
                    VirtualizationBasedSecurityStatus    = TryGetUInt(root, "VirtualizationBasedSecurityStatus"),
                    SecurityServicesConfigured           = TryGetUIntArray(root, "SecurityServicesConfigured"),
                    SecurityServicesRunning              = TryGetUIntArray(root, "SecurityServicesRunning"),
                    AvailableSecurityProperties          = TryGetUIntArray(root, "AvailableSecurityProperties"),
                    RequiredSecurityProperties           = TryGetUIntArray(root, "RequiredSecurityProperties"),
                    SecurityFeaturesEnabled              = TryGetUIntArray(root, "SecurityFeaturesEnabled"),
                    UsermodeCodeIntegrityPolicyEnforcementStatus = TryGetUInt(root, "UsermodeCodeIntegrityPolicyEnforcementStatus"),
                    InstanceIdentifier                   = TryGetString(root, "InstanceIdentifier"),
                    Version                              = TryGetString(root, "Version")
                };
            }
            catch
            {
                return null;
            }
        }

        // Conversions
        private static uint[]? ConvertToUIntArray(object? raw)
        {
            if (raw == null) return null;
            try
            {
                return raw switch
                {
                    uint[] u => u,
                    ushort[] us => us.Select(x => (uint)x).ToArray(),
                    int[] ia => ia.Select(x => (uint)x).ToArray(),
                    object[] oa => oa.Select(o =>
                    {
                        try { return Convert.ToUInt32(o); } catch { return (uint)0xFFFFFFFF; }
                    }).Where(v => v != 0xFFFFFFFF).ToArray(),
                    _ => null
                };
            }
            catch { return null; }
        }

        private static uint? TryGetUInt(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var el)) return null;
            return el.ValueKind == JsonValueKind.Number && el.TryGetUInt32(out var v) ? v : null;
        }

        private static uint[]? TryGetUIntArray(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var el)) return null;
            if (el.ValueKind == JsonValueKind.Null) return null;
            if (el.ValueKind == JsonValueKind.Number && el.TryGetUInt32(out var single)) return new[] { single };
            if (el.ValueKind == JsonValueKind.Array)
            {
                var arr = el.EnumerateArray()
                            .Where(e => e.ValueKind == JsonValueKind.Number && e.TryGetUInt32(out _))
                            .Select(e => e.GetUInt32())
                            .ToArray();
                return arr.Length == 0 ? null : arr;
            }
            return null;
        }

        private static string? TryGetString(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var el)) return null;
            return el.ValueKind == JsonValueKind.String ? el.GetString() : null;
        }

        private static DeviceGuardStatus Mark(DeviceGuardStatus status)
        {
            // Display and HasData are computed in DeviceGuardStatus; no assignments needed.
            return status;
        }

        private static bool IsRemote(string? machine) =>
            !string.IsNullOrWhiteSpace(machine) &&
            !machine.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !machine.Equals(".", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(machine, Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        private string? ResolvePsExecPath()
        {
            if (!string.IsNullOrWhiteSpace(PsExecCustomPath) && File.Exists(PsExecCustomPath))
                return PsExecCustomPath;

            var baseDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            string[] candidates =
            {
                Path.Combine(baseDir, "PsExec.exe"),
                @"C:\Sysinternals\PsExec.exe",
                Path.Combine(baseDir, "Tools","PsExec","PsExec.exe")
            };
            return candidates.FirstOrDefault(File.Exists);
        }

        private static string Escape(string s) => s.Replace("'", "''");
        private static string QuoteForCmd(string s) => "\"" + s.Replace("\"", "`\"") + "\"";
    }
}