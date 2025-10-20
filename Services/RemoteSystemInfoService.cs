using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Threading;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public sealed class RemoteSystemInfoService
    {
        public SystemInfo Get(string machine, TimeSpan timeout, CancellationToken ct)
        {
            var info = new SystemInfo();
            try
            {
                ct.ThrowIfCancellationRequested();
                var scope = new ManagementScope($@"\\{machine}\root\cimv2");
                scope.Connect();

                // Computer system
                var csQuery = new ObjectQuery("SELECT Name, Domain FROM Win32_ComputerSystem");
                using var csSearcher = new ManagementObjectSearcher(scope, csQuery);
                foreach (ManagementObject mo in csSearcher.Get())
                {
                    info.MachineName = (mo["Name"] as string) ?? info.MachineName;
                    var domain = mo["Domain"] as string;
                    if (!string.IsNullOrWhiteSpace(domain))
                        info.JoinType = domain.Equals(info.MachineName, StringComparison.OrdinalIgnoreCase)
                            ? "Workgroup"
                            : "Domain / Hybrid (Remote)";
                    break;
                }

                // Network adapters (first IPv4)
                var nicQuery = new ObjectQuery("SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");
                using var nicSearcher = new ManagementObjectSearcher(scope, nicQuery);
                foreach (ManagementObject mo in nicSearcher.Get())
                {
                    var arr = mo["IPAddress"] as string[];
                    var ip = arr?.FirstOrDefault(a => a.Contains("."));
                    if (!string.IsNullOrWhiteSpace(ip))
                    {
                        info.IPAddress = ip;
                        break;
                    }
                }

                // Remote user (best effort: logged-on user via Environment not available remotely, leave blank)
                info.CurrentUser = "(Remote context)";
            }
            catch (Exception ex)
            {
                info.MachineName = machine;
                info.IPAddress = "Unavailable";
                info.JoinType = "RemoteInfoError";
                info.CurrentUser = ex.GetType().Name;
            }
            return info;
        }
    }
}