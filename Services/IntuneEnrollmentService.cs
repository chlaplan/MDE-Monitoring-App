using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class IntuneEnrollmentService
    {
        private static readonly Regex GuidRegex = new(
            @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private const string EnrollmentsRoot = @"SOFTWARE\Microsoft\Enrollments";
        private const string ProviderIdValue = "ProviderID";
        private const string ProviderIdMatch = "MS DM Server";

        public IntuneEnrollmentInfo Get(string? targetMachine = null)
        {
            try
            {
                using var baseKey = string.IsNullOrWhiteSpace(targetMachine)
                    ? Registry.LocalMachine
                    : RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, targetMachine);

                using var enrollments = baseKey.OpenSubKey(EnrollmentsRoot);
                if (enrollments == null) return new IntuneEnrollmentInfo();

                var allSubKeyNames = enrollments.GetSubKeyNames();
                var intuneEntries = new List<IntuneEnrollmentInfo>();
                var configMgrFound = false;

                foreach (var sub in allSubKeyNames)
                {
                    using var subKey = enrollments.OpenSubKey(sub);
                    if (subKey == null) continue;

                    var provider = subKey.GetValue(ProviderIdValue) as string;
                    if (!string.Equals(provider, ProviderIdMatch, StringComparison.OrdinalIgnoreCase))
                        continue;

                    var enrollmentState = TryGetInt(subKey.GetValue("EnrollmentState"));
                    var upn = (subKey.GetValue("UPN") as string)?.Trim();
                    var curContainer = (subKey.GetValue("CurKeyContainer") as string)?.Trim();

                    var entry = new IntuneEnrollmentInfo
                    {
                        EnrollmentStateRaw = enrollmentState,
                        UPN = string.IsNullOrWhiteSpace(upn) ? "Unknown" : upn,
                        CurKeyContainer = string.IsNullOrWhiteSpace(curContainer) ? "Unknown" : curContainer
                    };

                    // Determine type for this entry
                    if (!string.IsNullOrWhiteSpace(curContainer))
                    {
                        if (curContainer.Equals("ConfigMgrEnrollment0", StringComparison.OrdinalIgnoreCase))
                        {
                            entry.Type = "ConfigMgr";
                            configMgrFound = true;
                        }
                        else if (curContainer.StartsWith("tr-", StringComparison.OrdinalIgnoreCase) ||
                                 GuidRegex.IsMatch(curContainer))
                        {
                            entry.Type = "Intune";
                        }
                        else
                        {
                            entry.Type = "Unknown";
                        }
                    }
                    intuneEntries.Add(entry);
                }

                if (intuneEntries.Count == 0) return new IntuneEnrollmentInfo();

                // If we have both Intune and ConfigMgr markers, mark co-managed
                var hasIntune = intuneEntries.Any(e => e.Type == "Intune");
                var hasConfig = intuneEntries.Any(e => e.Type == "ConfigMgr") || configMgrFound;

                if (hasIntune && hasConfig)
                {
                    // Merge into a synthesized co-managed info (prefer Intune UPN)
                    var primary = intuneEntries.First(e => e.Type == "Intune");
                    primary.Type = "Co-managed (Intune + ConfigMgr)";
                    return primary;
                }

                // Prefer Intune entry if multiple
                var chosen = intuneEntries.FirstOrDefault(e => e.Type == "Intune")
                             ?? intuneEntries.First();
                return chosen;
            }
            catch
            {
                return new IntuneEnrollmentInfo();
            }
        }

        private static int? TryGetInt(object? raw)
        {
            if (raw == null) return null;
            try
            {
                if (raw is int i) return i;
                if (int.TryParse(raw.ToString(), out var v)) return v;
                return null;
            }
            catch { return null; }
        }
    }
}