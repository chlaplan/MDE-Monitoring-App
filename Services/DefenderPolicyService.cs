using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class DefenderPolicyService
    {
        private const string PolicyKeyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager";
        private const string DefinitionsRelativePath = @"Data\DefenderPolicyDefinitions.json";

        // Remote execution options (set by ViewModel)
        public bool UsePsExec { get; set; }
        public string? PsExecCustomPath { get; set; }

        private static readonly Regex GuidRegex = new(
            @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Dictionary<string, string> AsrRuleNames = new(StringComparer.OrdinalIgnoreCase)
        {
            { "56A863A9-875E-4185-98A7-B882C64B5CE5", "Block abuse of exploited vulnerable signed drivers" },
            { "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", "Block Adobe Reader from creating child processes" },
            { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Block all Office applications from creating child processes" },
            { "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "Block credential stealing from LSASS" },
            { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "Block executable content from email client and webmail" },
            { "01443614-CD74-433A-B99E-2ECDC07BFC25", "Block executable files unless they meet prevalence, age, or trusted list criteria" },
            { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "Block execution of potentially obfuscated scripts" },
            { "D3E037E1-3EB8-44C8-A917-57927947596D", "Block JavaScript or VBScript from launching downloaded executable content" },
            { "3B576869-A4EC-4529-8536-B80A7769E899", "Block Office applications from creating executable content" },
            { "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "Block Office applications from injecting code into other processes" },
            { "26190899-1602-49E8-8B27-EB1D0A1CE869", "Block Office communication application from creating child processes" },
            { "E6DB77E5-3DF2-4CF1-B95A-636979351E5B", "Block persistence through WMI event subscription" },
            { "D1E49AAC-8F56-4280-B9BA-993A6D77406C", "Block process creations originating from PSExec and WMI commands" },
            { "33DDEDF1-C6E0-47CB-833E-DE6133960387", "Block rebooting machine in Safe Mode" },
            { "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", "Block untrusted and unsigned processes running from USB" },
            { "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB", "Block use of copied or impersonated system tools" },
            { "A8F5898E-1DC8-49A9-9878-85004B8A61E6", "Block Webshell creation for Servers" },
            { "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "Block Win32 API calls from Office macros" },
            { "C1DB55AB-C21A-4637-BB3F-A12568109D35", "Use advanced protection against ransomware" }
        };

        private readonly Dictionary<string, DefenderPolicyDefinition> _defs;
        private readonly bool _defsLoaded;
        private readonly List<string> _attemptedPaths = new();
        public bool DefinitionsLoaded => _defsLoaded;
        public IReadOnlyList<string> AttemptedDefinitionPaths => _attemptedPaths;

        public DefenderPolicyService()
        {
            _defs = LoadDefinitions(out _defsLoaded);
        }

        public IEnumerable<PolicySetting> LoadPolicies() => LoadPolicies(null);

        public IEnumerable<PolicySetting> LoadPolicies(string? targetMachine)
        {
            bool remote = IsRemote(targetMachine);
            if (!remote)
                return LoadPoliciesLocal();

            string host = targetMachine!;

            if (UsePsExec)
            {
                var psExecResult = TryLoadPoliciesViaPsExec(host);
                if (psExecResult != null)
                    return psExecResult;
                // fall back if PsExec failed
            }

            // Remote Registry
            try
            {
                using var remoteHKLM = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host);
                using var key = remoteHKLM.OpenSubKey(PolicyKeyPath);
                if (key != null)
                {
                    var list = ReadRegistryKeyValues(key);
                    list.Insert(0, BuildDefinitionsStatusRow());
                    list.Insert(0, new PolicySetting
                    {
                        DisplayName = UsePsExec ? "Remote Source (RR after PsExec fail)" : "Remote Source (RR)",
                        RawValue = host,
                        InterpretedValue = host,
                        Description = "Policies read via Remote Registry",
                        Severity = "Info"
                    });
                    return list.OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
                }
            }
            catch { /* ignore, try fallbacks */ }

            // WinRM Invoke-Command (PowerShell)
            var psFallback = TryLoadPoliciesViaPsRemoting(host);
            if (psFallback != null) return psFallback;

            // reg.exe via WinRM
            var regExeFallback = TryLoadPoliciesViaRegExe(host);
            if (regExeFallback != null) return regExeFallback;

            // All failed
            return new[]
            {
                BuildDefinitionsStatusRow(),
                new PolicySetting
                {
                    DisplayName = "Remote Retrieval Failure",
                    RawValue = host,
                    InterpretedValue = "Error",
                    Description = "Remote Registry + WinRM + reg.exe fallback failed.",
                    Severity = "Error"
                },
                RemoteConnectivityHint(host)
            };
        }

        private IEnumerable<PolicySetting> LoadPoliciesLocal()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PolicyKeyPath);
                if (key == null)
                    return new[]
                    {
                        BuildDefinitionsStatusRow(),
                        new PolicySetting
                        {
                            DisplayName = "Policy Manager Key",
                            RawValue = "(missing)",
                            InterpretedValue = "Missing",
                            Description = "Registry key not found",
                            Severity = "Info"
                        }
                    };

                var list = ReadRegistryKeyValues(key);
                list.Insert(0, BuildDefinitionsStatusRow());
                return list.OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
            }
            catch (Exception ex)
            {
                return new[]
                {
                    BuildDefinitionsStatusRow(),
                    new PolicySetting
                    {
                        DisplayName = "Local Retrieval Failure",
                        RawValue = ex.GetType().Name,
                        InterpretedValue = "Error",
                        Description = ex.Message,
                        Severity = "Error"
                    }
                };
            }
        }

        // --- Registry key value reading (shared local & remote) ---
        private List<PolicySetting> ReadRegistryKeyValues(RegistryKey key)
        {
            var list = new List<PolicySetting>();
            foreach (var name in key.GetValueNames())
            {
                var rawObj = key.GetValue(name);
                var rawStr = rawObj?.ToString() ?? "";

                if (string.Equals(name, "ASRRules", StringComparison.OrdinalIgnoreCase))
                    list.AddRange(ParseAsrRules(rawStr));
                else if (string.Equals(name, "ASRConfig", StringComparison.OrdinalIgnoreCase))
                    list.Add(ParseDelimitedListSummary(name, rawStr, "ASR Global Exclusions", true));
                else if (string.Equals(name, "ASRRuleExclusions", StringComparison.OrdinalIgnoreCase))
                    list.AddRange(ParseAsrPerRuleExclusions(rawStr));
                else if (string.Equals(name, "AllowedApplications", StringComparison.OrdinalIgnoreCase))
                    list.Add(ParseAllowedApplications(rawStr));
                else if (string.Equals(name, "ThreatSeverityDefaultAction", StringComparison.OrdinalIgnoreCase))
                    list.AddRange(ParseThreatSeverityDefaultAction(rawStr));
                else
                    list.Add(InterpretSimple(name, rawStr));
            }
            return list;
        }

        // --- PsExec (reg query UNC) ---
        private IEnumerable<PolicySetting>? TryLoadPoliciesViaPsExec(string machine)
        {
            var psExecPath = ResolvePsExecPath();
            if (psExecPath == null)
            {
                return new[]
                {
                    BuildDefinitionsStatusRow(),
                    new PolicySetting
                    {
                        DisplayName = "Remote Source (PsExec)",
                        RawValue = machine,
                        InterpretedValue = "Unavailable",
                        Description = "PsExec.exe not found.",
                        Severity = "Warning"
                    }
                };
            }

            string uncKeyPath = $"\\\\{machine}\\HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager";
            string regQuery = $"reg query \"{uncKeyPath}\" /s";
            string arguments = $"\\\\{machine} -accepteula -n 10 -h -s cmd /c \"{regQuery}\"";

            var psi = new ProcessStartInfo
            {
                FileName = psExecPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            try
            {
                using var proc = Process.Start(psi);
                if (proc == null) return null;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                if (proc.ExitCode != 0)
                {
                    return new[]
                    {
                        BuildDefinitionsStatusRow(),
                        new PolicySetting
                        {
                            DisplayName = "Remote Source (PsExec)",
                            RawValue = machine,
                            InterpretedValue = "Error",
                            Description = $"PsExec exit code {proc.ExitCode}. {Truncate(stderr)}",
                            Severity = "Error"
                        }
                    };
                }

                if (!stdout.Contains("Policy Manager", StringComparison.OrdinalIgnoreCase))
                {
                    return new[]
                    {
                        BuildDefinitionsStatusRow(),
                        new PolicySetting
                        {
                            DisplayName = "Remote Source (PsExec)",
                            RawValue = machine,
                            InterpretedValue = "Missing",
                            Description = "Policy Manager key not found via PsExec.",
                            Severity = "Info"
                        }
                    };
                }

                var list = ParseRegQueryOutput(stdout);
                list.Insert(0, BuildDefinitionsStatusRow());
                list.Insert(0, new PolicySetting
                {
                    DisplayName = "Remote Source (PsExec)",
                    RawValue = machine,
                    InterpretedValue = machine,
                    Description = "Policies read via PsExec reg query (/s).",
                    Severity = "Info"
                });

                // Add hint if ASRRules not found
                if (!list.Any(p => p.DisplayName.Contains("ASR Rule", StringComparison.OrdinalIgnoreCase)))
                {
                    list.Add(new PolicySetting
                    {
                        DisplayName = "ASRRules Status",
                        RawValue = "(absent)",
                        InterpretedValue = "Not Found",
                        Description = "ASRRules value not present or failed to parse in PsExec output.",
                        Severity = "Warning"
                    });
                }

                return list.OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
            }
            catch (Exception ex)
            {
                return new[]
                {
                    BuildDefinitionsStatusRow(),
                    new PolicySetting
                    {
                        DisplayName = "Remote Source (PsExec)",
                        RawValue = machine,
                        InterpretedValue = "Error",
                        Description = "PsExec exception: " + ex.Message,
                        Severity = "Error"
                    }
                };
            }
        }

        // Parse reg query /s output (multi-line REG_SZ and DWORD normalization)
        private List<PolicySetting> ParseRegQueryOutput(string output)
        {
            var result = new List<PolicySetting>();
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            var valueLineRegex = new Regex(@"^\s+(\S+)\s+REG_(\S+)\s+(.+)$", RegexOptions.Compiled);
            string? currentName = null;
            string? currentType = null;
            var currentData = new StringBuilder();

            void FinalizeCurrent()
            {
                if (currentName == null) return;
                string data = currentData.ToString().TrimEnd();

                if (string.Equals(currentType, "DWORD", StringComparison.OrdinalIgnoreCase))
                    data = NormalizeDword(data);

                if (string.Equals(currentName, "ASRRules", StringComparison.OrdinalIgnoreCase))
                {
                    result.AddRange(ParseAsrRules(data));
                }
                else if (string.Equals(currentName, "ASRConfig", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(ParseDelimitedListSummary(currentName, data, "ASR Global Exclusions", true));
                }
                else if (string.Equals(currentName, "ASRRuleExclusions", StringComparison.OrdinalIgnoreCase))
                {
                    result.AddRange(ParseAsrPerRuleExclusions(data));
                }
                else if (string.Equals(currentName, "AllowedApplications", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(ParseAllowedApplications(data));
                }
                else if (string.Equals(currentName, "ThreatSeverityDefaultAction", StringComparison.OrdinalIgnoreCase))
                {
                    result.AddRange(ParseThreatSeverityDefaultAction(data));
                }
                else if (string.Equals(currentName, "PolicyGroups", StringComparison.OrdinalIgnoreCase))
                {
                    // PsExec variant: match non-PsExec formatting => Device Control Groups, raw XML in RawValue.
                    int groupCount = CountOccurrences(data, "<Group Id=");
                    result.Add(new PolicySetting
                    {
                        DisplayName = "Device Control Groups",
                        RawValue = data,                       // full XML in RAW column
                        InterpretedValue = $"{groupCount} group(s)",
                        Description = "Raw XML (PolicyGroups)",
                        Severity = groupCount > 0 ? "Info" : "Warning"
                    });
                }
                else if (string.Equals(currentName, "PolicyRules", StringComparison.OrdinalIgnoreCase))
                {
                    int ruleCount = CountOccurrences(data, "<PolicyRule Id=");
                    result.Add(new PolicySetting
                    {
                        DisplayName = "Device Control Rules",
                        RawValue = data,                       // full XML in RAW column
                        InterpretedValue = $"{ruleCount} rule(s)",
                        Description = "Raw XML (PolicyRules)",
                        Severity = ruleCount > 0 ? "Info" : "Warning"
                    });
                }
                else
                {
                    result.Add(InterpretSimple(currentName, data));
                }

                currentName = null;
                currentType = null;
                currentData.Clear();
            }

            foreach (var line in lines)
            {
                if (line.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
                {
                    FinalizeCurrent();
                    continue;
                }

                var m = valueLineRegex.Match(line);
                if (m.Success)
                {
                    FinalizeCurrent();
                    currentName = m.Groups[1].Value;
                    currentType = m.Groups[2].Value;
                    currentData.AppendLine(m.Groups[3].Value);
                }
                else
                {
                    if (currentName != null)
                        currentData.AppendLine(line);
                }
            }
            FinalizeCurrent();

            return result;
        }

        private PolicySetting BuildXmlSummary(string displayName, string xml, string token)
        {
            int count = CountOccurrences(xml, token);
            return new PolicySetting
            {
                DisplayName = displayName,
                RawValue = "(xml)",
                InterpretedValue = $"{count} item(s)",
                Description = Shorten(xml),
                Severity = count > 0 ? "Info" : "Warning"
            };
        }

        private static int CountOccurrences(string text, string token)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            int count = 0, idx = 0;
            while ((idx = text.IndexOf(token, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                count++;
                idx += token.Length;
            }
            return count;
        }

        private static string Shorten(string s) =>
            string.IsNullOrWhiteSpace(s) ? "(empty)" : (s.Length <= 240 ? s.Trim() : s.Trim().Substring(0, 240) + "...");

        private static string NormalizeDword(string data)
        {
            var d = data.Trim();
            if (d.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(d.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int val))
                    return val.ToString(CultureInfo.InvariantCulture);
            }
            return d;
        }

        // --- PowerShell Invoke-Command fallback ---
        private IEnumerable<PolicySetting>? TryLoadPoliciesViaPsRemoting(string machine)
        {
            try
            {
                var script = $@"Invoke-Command -ComputerName '{Escape(machine)}' -ScriptBlock {{
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    if (-not (Test-Path $base)) {{ 'MISSING_KEY'; return }}
    Get-ItemProperty -Path $base | Select-Object * | ForEach-Object {{
        $_.PSObject.Properties | ForEach-Object {{
            if ($_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {{
                ($_.Name + '=' + ($_.Value))
            }}
        }}
    }}
}}";

                var psi = new ProcessStartInfo("powershell.exe", "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command " + Quote(script))
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return null;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                if (proc.ExitCode != 0 || stderr.Length > 0) return null;
                if (stdout.Contains("MISSING_KEY"))
                    return MissingKeyResult(machine);

                var list = new List<PolicySetting>();
                foreach (var line in stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int idx = line.IndexOf('=');
                    if (idx <= 0) continue;
                    string name = line.Substring(0, idx).Trim();
                    string value = line.Substring(idx + 1).Trim();

                    if (string.Equals(name, "ASRRules", StringComparison.OrdinalIgnoreCase))
                        list.AddRange(ParseAsrRules(value));
                    else if (string.Equals(name, "ASRConfig", StringComparison.OrdinalIgnoreCase))
                        list.Add(ParseDelimitedListSummary(name, value, "ASR Global Exclusions", true));
                    else if (string.Equals(name, "ASRRuleExclusions", StringComparison.OrdinalIgnoreCase))
                        list.AddRange(ParseAsrPerRuleExclusions(value));
                    else if (string.Equals(name, "AllowedApplications", StringComparison.OrdinalIgnoreCase))
                        list.Add(ParseAllowedApplications(value));
                    else if (string.Equals(name, "ThreatSeverityDefaultAction", StringComparison.OrdinalIgnoreCase))
                        list.AddRange(ParseThreatSeverityDefaultAction(value));
                    else
                        list.Add(InterpretSimple(name, value));
                }

                list.Insert(0, BuildDefinitionsStatusRow());
                list.Insert(0, new PolicySetting
                {
                    DisplayName = "Remote Source (WinRM)",
                    RawValue = machine,
                    InterpretedValue = machine,
                    Description = "Policies read via PowerShell Invoke-Command",
                    Severity = "Info"
                });
                return list.OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
            }
            catch { return null; }
        }

        // --- reg.exe via Invoke-Command fallback ---
        private IEnumerable<PolicySetting>? TryLoadPoliciesViaRegExe(string machine)
        {
            try
            {
                var script = $@"Invoke-Command -ComputerName '{Escape(machine)}' -ScriptBlock {{
    $key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $lines = & reg.exe query $key 2>$null
    if (-not $lines) {{ 'REG_MISSING_KEY'; return }}
    $lines | ForEach-Object {{
        if ($_ -match '^\s+(\S+)\s+REG_\S+\s+(.+)$') {{
            $name = $Matches[1]; $data = $Matches[2]; $name + '=' + $data
        }}
    }}
}}";

                var psi = new ProcessStartInfo("powershell.exe", "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command " + Quote(script))
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return null;
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                if (proc.ExitCode != 0) return null;
                if (stdout.Contains("REG_MISSING_KEY")) return MissingKeyResult(machine);

                var list = new List<PolicySetting>();
                foreach (var line in stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int idx = line.IndexOf('=');
                    if (idx <= 0) continue;
                    string name = line.Substring(0, idx).Trim();
                    string value = line.Substring(idx + 1).Trim();

                    if (string.Equals(name, "ASRRules", StringComparison.OrdinalIgnoreCase))
                        list.AddRange(ParseAsrRules(value));
                    else if (string.Equals(name, "ASRConfig", StringComparison.OrdinalIgnoreCase))
                        list.Add(ParseDelimitedListSummary(name, value, "ASR Global Exclusions", true));
                    else if (string.Equals(name, "ASRRuleExclusions", StringComparison.OrdinalIgnoreCase))
                        list.AddRange(ParseAsrPerRuleExclusions(value));
                    else if (string.Equals(name, "AllowedApplications", StringComparison.OrdinalIgnoreCase))
                        list.Add(ParseAllowedApplications(value));
                    else if (string.Equals(name, "ThreatSeverityDefaultAction", StringComparison.OrdinalIgnoreCase))
                        list.AddRange(ParseThreatSeverityDefaultAction(value));
                    else
                        list.Add(InterpretSimple(name, value));
                }

                list.Insert(0, BuildDefinitionsStatusRow());
                list.Insert(0, new PolicySetting
                {
                    DisplayName = "Remote Source (reg.exe)",
                    RawValue = machine,
                    InterpretedValue = machine,
                    Description = "Policies read via reg.exe over WinRM",
                    Severity = "Info"
                });
                return list.OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
            }
            catch { return null; }
        }

        // --- ASR rules parsing (supports '|' separators) ---
        private IEnumerable<PolicySetting> ParseAsrRules(object? raw)
        {
            var s = raw?.ToString();
            if (string.IsNullOrWhiteSpace(s)) yield break;

            var tokens = s.Split(new[] { '|', ';', ',', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var t in tokens)
            {
                var parts = t.Split('=');
                if (parts.Length != 2) continue;
                var guid = parts[0].Trim();
                var state = parts[1].Trim();
                if (!GuidRegex.IsMatch(guid)) continue;

                string friendly = AsrRuleNames.TryGetValue(guid.ToUpperInvariant(), out var name) ? name : "Unknown ASR Rule";
                string interpreted = state switch
                {
                    "0" => "Disabled",
                    "1" => "Enabled",
                    "2" => "Audit",
                    "6" => "Warn",
                    _ => "Unknown(" + state + ")"
                };

                yield return new PolicySetting
                {
                    DisplayName = friendly,
                    RawValue = state,
                    InterpretedValue = interpreted,
                    Description = guid,
                    Severity = interpreted == "Disabled" ? "Risk" : "Info"
                };
            }
        }

        private PolicySetting ParseDelimitedListSummary(string name, object? raw, string displayName, bool preserveDescription)
        {
            var text = raw?.ToString() ?? "";
            var items = text.Split(new[] { '\r', '\n', ';', ',', '|' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(v => v.Trim()).Where(v => v.Length > 0).Take(50).ToList();

            string summary = items.Count == 0
                ? "(none)"
                : (items.Count <= 5 ? string.Join(", ", items) : string.Join(", ", items.Take(5)) + $" ... (+{items.Count - 5})");

            return new PolicySetting
            {
                DisplayName = displayName,
                RawValue = text.Length == 0 ? "(empty)" : "(list)",
                InterpretedValue = summary,
                Description = preserveDescription ? name : $"{items.Count} item(s)",
                Severity = "Info"
            };
        }

        private PolicySetting ParseAllowedApplications(object? raw) =>
            ParseDelimitedListSummary("AllowedApplications", raw, "Allowed Applications (Summary)", false);

        private IEnumerable<PolicySetting> ParseAsrPerRuleExclusions(object? raw)
        {
            var text = raw?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(text)) yield break;

            var ruleSegments = text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var seg in ruleSegments)
            {
                var kv = seg.Split('=');
                if (kv.Length != 2) continue;
                var guid = kv[0].Trim();
                var entries = kv[1].Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(v => v.Trim()).Where(v => v.Length > 0).ToList();
                if (entries.Count == 0) continue;
                string friendly = AsrRuleNames.TryGetValue(guid.ToUpperInvariant(), out var name) ? name : "ASR Rule (Exclusions)";

                yield return new PolicySetting
                {
                    DisplayName = friendly + " Exclusions",
                    RawValue = "(list)",
                    InterpretedValue = entries.Count <= 5
                        ? string.Join(", ", entries)
                        : string.Join(", ", entries.Take(5)) + $" ... (+{entries.Count - 5})",
                    Description = guid,
                    Severity = "Info"
                };
            }
        }

        private IEnumerable<PolicySetting> ParseThreatSeverityDefaultAction(object? raw)
        {
            var text = raw?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(text)) yield break;

            var parts = text.Split(new[] { '|', ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var kv = part.Split('=');
                if (kv.Length != 2) continue;
                yield return new PolicySetting
                {
                    DisplayName = "Threat Severity Action (" + kv[0] + ")",
                    RawValue = kv[1],
                    InterpretedValue = kv[1],
                    Description = "Default action for severity: " + kv[0],
                    Severity = "Info"
                };
            }
        }

        private PolicySetting InterpretSimple(string name, object? raw)
        {
            string rawText = raw?.ToString() ?? "";
            if (_defsLoaded && _defs.TryGetValue(name, out var def))
            {
                string interpreted = rawText;
                switch (def.Kind)
                {
                    case "disableFlag":
                        interpreted = rawText == "1" ? "Disabled" : "Enabled";
                        break;
                    case "allowFlag":
                        interpreted = rawText == "1" ? "Enabled" : "Disabled";
                        break;
                    case "enum":
                        if (def.EnumMap != null && def.EnumMap.TryGetValue(rawText, out var mapped))
                            interpreted = mapped;
                        break;
                    case "percent":
                        interpreted = rawText + "%";
                        break;
                }
                return new PolicySetting
                {
                    DisplayName = def.DisplayName ?? name,
                    RawValue = rawText,
                    InterpretedValue = interpreted,
                    Description = def.Description ?? "",
                    Severity = (def.Kind == "disableFlag" && rawText == "1") ? "Risk" : (def.DefaultSeverity ?? "Info")
                };
            }

            return new PolicySetting
            {
                DisplayName = name,
                RawValue = rawText,
                InterpretedValue = rawText,
                Description = "Unmapped Defender policy value",
                Severity = "Info"
            };
        }

        private PolicySetting BuildDefinitionsStatusRow() =>
            new()
            {
                DisplayName = "Definitions Load",
                RawValue = _defsLoaded ? "Loaded" : "NotLoaded",
                InterpretedValue = _defsLoaded ? "OK" : "Missing",
                Description = _defsLoaded
                    ? $"Definitions loaded from {_attemptedPaths.FirstOrDefault(p => File.Exists(p))}"
                    : "Definitions JSON not loaded. Attempted: " + string.Join(" | ", _attemptedPaths),
                Severity = _defsLoaded ? "Info" : "Warning"
            };

        private IEnumerable<PolicySetting> MissingKeyResult(string machine) =>
            new[]
            {
                BuildDefinitionsStatusRow(),
                new PolicySetting
                {
                    DisplayName = "Remote Source",
                    RawValue = machine,
                    InterpretedValue = "Missing",
                    Description = "Policy Manager key not found.",
                    Severity = "Info"
                },
                RemoteConnectivityHint(machine)
            };

        private PolicySetting RemoteConnectivityHint(string machine) =>
            new()
            {
                DisplayName = "Remote Connectivity Hint",
                RawValue = machine,
                InterpretedValue = "Troubleshoot",
                Description = "Verify Remote Registry service, firewall RPC/DCOM rules, WinRM enabled (Enable-PSRemoting -Force), correct hostname/FQDN, admin credentials. If PsExec used, ensure elevation and valid path.",
                Severity = "Warning"
            };

        private Dictionary<string, DefenderPolicyDefinition> LoadDefinitions(out bool loaded)
        {
            loaded = false;
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            };
            string?[] bases =
            {
                AppContext.BaseDirectory,
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                Environment.CurrentDirectory
            };

            foreach (var b in bases.Where(p => !string.IsNullOrWhiteSpace(p)))
            {
                var full = Path.Combine(b!, DefinitionsRelativePath);
                _attemptedPaths.Add(full);
                if (!File.Exists(full)) continue;
                try
                {
                    var json = File.ReadAllText(full);
                    var defs = JsonSerializer.Deserialize<List<DefenderPolicyDefinition>>(json, options) ?? new();
                    loaded = true;
                    return defs
                        .Where(d => !string.IsNullOrWhiteSpace(d.Name))
                        .GroupBy(d => d.Name.Trim(), StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
                }
                catch (Exception ex)
                {
                    _attemptedPaths.Add("Read error: " + ex.Message);
                }
            }
            return new(StringComparer.OrdinalIgnoreCase);
        }

        private static bool IsRemote(string? host) =>
            !string.IsNullOrWhiteSpace(host) &&
            !host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !host.Equals(".", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(host, Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        private string? ResolvePsExecPath()
        {
            if (!string.IsNullOrWhiteSpace(PsExecCustomPath) && File.Exists(PsExecCustomPath))
                return PsExecCustomPath;
            var baseDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
            foreach (var c in new[]
            {
                Path.Combine(baseDir, "PsExec.exe"),
                @"C:\Sysinternals\PsExec.exe",
                Path.Combine(baseDir, "Tools","PsExec","PsExec.exe")
            })
                if (File.Exists(c)) return c;
            return null;
        }

        private static string Escape(string s) => s.Replace("'", "''");
        private static string Quote(string s) => "\"" + s.Replace("\"", "`\"") + "\"";
        private static string Truncate(string s) => s.Length <= 350 ? s : s.Substring(0, 350) + "...";
    }
}