using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class DefenderPolicyService
    {
        private const string PolicyKeyPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager";
        private const string DefinitionsRelativePath = @"Data\DefenderPolicyDefinitions.json";
        private const string AsrReferenceUrl = "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference";

        private static readonly Regex GuidRegex = new(
            @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

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

        public DefenderPolicyService()
        {
            _defs = LoadDefinitions(out _defsLoaded);
        }

        public async Task RefreshAsrRuleNamesFromReferenceAsync()
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                var html = await client.GetStringAsync(AsrReferenceUrl).ConfigureAwait(false);

                foreach (Match m in GuidRegex.Matches(html))
                {
                    var guid = m.Value.ToUpperInvariant();
                    if (AsrRuleNames.ContainsKey(guid)) continue;

                    int start = Math.Max(0, m.Index - 160);
                    int len = Math.Min(300, html.Length - start);
                    var window = html.Substring(start, len);
                    var cleaned = Regex.Replace(window, @"\s+", " ").Trim();
                    string guess = cleaned.Split(guid, StringSplitOptions.RemoveEmptyEntries)[0];
                    var parts = guess.Split(new[] { '.', '>' }, StringSplitOptions.RemoveEmptyEntries);
                    guess = parts.LastOrDefault()?.Trim() ?? "Unlabeled ASR Rule";
                    if (guess.Length > 120) guess = guess[^120..];
                    if (string.IsNullOrWhiteSpace(guess)) guess = "Unlabeled ASR Rule";
                    AsrRuleNames[guid] = guess;
                }
            }
            catch
            {
                // Best-effort only
            }
        }

        private Dictionary<string, DefenderPolicyDefinition> LoadDefinitions(out bool loaded)
        {
            loaded = false;

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            };

            string?[] probeBases =
            {
                AppContext.BaseDirectory,
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                Environment.CurrentDirectory
            };

            foreach (var b in probeBases.Where(p => !string.IsNullOrWhiteSpace(p)))
            {
                var full = Path.Combine(b!, DefinitionsRelativePath);
                _attemptedPaths.Add(full);
                if (!File.Exists(full)) continue;
                try
                {
                    var json = File.ReadAllText(full);
                    var items = JsonSerializer.Deserialize<List<DefenderPolicyDefinition>>(json, jsonOptions) ?? new();
                    loaded = true;
                    return items
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

        public IEnumerable<PolicySetting> LoadPolicies()
        {
            var list = new List<PolicySetting>();

            if (!_defsLoaded)
            {
                list.Add(new PolicySetting
                {
                    Name = "(Definitions Missing)",
                    DisplayName = "Definitions File Not Loaded",
                    InterpretedValue = "N/A",
                    Description = "Tried: " + string.Join(" | ", _attemptedPaths),
                    Severity = "Info"
                });
            }

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(PolicyKeyPath);
                if (key == null)
                {
                    list.Add(new PolicySetting
                    {
                        Name = "(MissingKey)",
                        DisplayName = "Policy Manager Key Missing",
                        InterpretedValue = "N/A",
                        Description = PolicyKeyPath,
                        Severity = "Info"
                    });
                    return list;
                }

                var valueNames = key.GetValueNames();
                if (valueNames.Length == 0)
                {
                    list.Add(new PolicySetting
                    {
                        Name = "(Empty)",
                        DisplayName = "No Policy Values",
                        InterpretedValue = "N/A",
                        Description = "Key present but empty.",
                        Severity = "Info"
                    });
                }
                else
                {
                    foreach (var name in valueNames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
                    {
                        var raw = key.GetValue(name);
                        if (name.Equals("ASRRules", StringComparison.OrdinalIgnoreCase))
                        { list.AddRange(ParseAsrRules(raw)); continue; }
                        if (name.Equals("ASROnlyExclusions", StringComparison.OrdinalIgnoreCase))
                        { list.Add(ParseDelimitedListSummary(name, raw, "ASR Global Exclusions", false)); continue; }
                        if (name.Equals("ASROnlyPerRuleExclusions", StringComparison.OrdinalIgnoreCase))
                        { list.AddRange(ParseAsrPerRuleExclusions(raw)); continue; }
                        if (name.Equals("AllowedApplications", StringComparison.OrdinalIgnoreCase))
                        { list.Add(ParseAllowedApplications(raw)); continue; }
                        if (name.Equals("ThreatSeverityDefaultAction", StringComparison.OrdinalIgnoreCase))
                        { list.AddRange(ParseThreatSeverityDefaultAction(raw)); continue; }

                        list.Add(InterpretSimple(name, raw));
                    }
                }
            }
            catch (Exception ex)
            {
                list.Add(new PolicySetting
                {
                    Name = "Error",
                    DisplayName = "Policy Retrieval Failed",
                    InterpretedValue = "N/A",
                    RawValue = ex.Message,
                    Description = "Failed to read registry (run elevated?).",
                    Severity = "Error"
                });
            }

            return list
                .OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private PolicySetting InterpretSimple(string name, object? raw)
        {
            var trimmed = name.Trim();
            _defs.TryGetValue(trimmed, out var def);
            var rawStr = raw?.ToString() ?? "";

            if (def == null)
            {
                return new PolicySetting
                {
                    Name = trimmed,
                    DisplayName = trimmed,
                    RawValue = raw,
                    InterpretedValue = rawStr,
                    Description = "Unmapped Defender policy value.",
                    Severity = "Info"
                };
            }

            string interpreted = rawStr;
            string severity = def.DefaultSeverity ?? "Info";
            string kind = def.Kind?.ToLowerInvariant() ?? "raw";

            switch (kind)
            {
                case "disableflag":
                {
                    bool disabled = rawStr == "1";
                    interpreted = disabled
                        ? def.DisabledMeaning ?? "Disabled"
                        : def.EnabledMeaning ?? "Enabled";
                    if (disabled && !string.IsNullOrEmpty(def.RiskWhenDisabled))
                        severity = def.RiskWhenDisabled;
                    break;
                }
                case "allowflag":
                {
                    bool enabled = rawStr == "1";
                    interpreted = enabled
                        ? def.EnabledMeaning ?? "Enabled"
                        : def.DisabledMeaning ?? "Disabled";
                    if (!enabled && !string.IsNullOrEmpty(def.RiskWhenDisabled))
                        severity = def.RiskWhenDisabled;
                    break;
                }
                case "enum":
                    if (def.EnumMap != null && def.EnumMap.TryGetValue(rawStr, out var mapped))
                        interpreted = mapped;
                    else
                        interpreted = $"Unknown ({rawStr})";
                    break;
                case "percent":
                    interpreted = int.TryParse(rawStr, out var pct) ? pct + "%" : rawStr;
                    break;
                case "integer":
                    if (trimmed.Equals("ScheduleScanTime", StringComparison.OrdinalIgnoreCase) ||
                        trimmed.Equals("ScheduleQuickScanTime", StringComparison.OrdinalIgnoreCase))
                    {
                        if (int.TryParse(rawStr, out var minutes))
                            interpreted = MinutesToTime(minutes);
                    }
                    break;
            }

            return new PolicySetting
            {
                Name = trimmed,
                DisplayName = def.DisplayName,
                RawValue = raw,
                InterpretedValue = interpreted,
                Description = def.Description,
                Severity = severity
            };
        }

        private IEnumerable<PolicySetting> ParseAsrRules(object? raw)
        {
            var list = new List<PolicySetting>();
            var rawStr = raw?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(rawStr))
            {
                list.Add(new PolicySetting
                {
                    Name = "ASRRules",
                    DisplayName = "ASR Rules",
                    RawValue = raw,
                    InterpretedValue = "None",
                    Description = "No ASR rules configured.",
                    Severity = "Info"
                });
                return list;
            }

            var parts = rawStr.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                var kv = part.Split('=', 2);
                if (kv.Length != 2) continue;
                var guidRaw = kv[0].Trim();
                var guid = guidRaw.ToUpperInvariant();
                var state = kv[1].Trim();

                string friendly = AsrRuleNames.TryGetValue(guid, out var fn) ? fn : guidRaw;
                string interpreted = state switch
                {
                    "0" => "Disabled",
                    "1" => "Enabled",
                    "2" => "Audit",
                    _ => $"State {state}"
                };
                string severity = state == "0" ? "Risk" : "Info";
                list.Add(new PolicySetting
                {
                    Name = $"ASRRules:{guid}",
                    DisplayName = $"ASR: {friendly}",
                    RawValue = state,
                    InterpretedValue = interpreted,
                    Description = "Attack Surface Reduction rule configuration.",
                    Severity = severity
                });
            }
            return list;
        }

        private PolicySetting ParseDelimitedListSummary(string name, object? raw, string displayName, bool preserveDescription)
        {
            var rawStr = raw?.ToString() ?? "";
            var items = rawStr.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            string preview = string.Join(" | ", items.Take(3));
            if (items.Length > 3) preview += $" ... (+{items.Length - 3})";

            _defs.TryGetValue(name, out var def);

            return new PolicySetting
            {
                Name = name,
                DisplayName = displayName,
                RawValue = rawStr,
                InterpretedValue = $"{items.Length} item(s)",
                Description = preserveDescription
                    ? def?.Description ?? (items.Length == 0 ? "No entries." : preview)
                    : (items.Length == 0 ? "No entries." : preview),
                Severity = "Info"
            };
        }

        private PolicySetting ParseAllowedApplications(object? raw)
        {
            var rawStr = raw?.ToString() ?? "";
            var items = rawStr.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            string preview = string.Join(" | ", items.Take(2));
            if (items.Length > 2) preview += $" ... (+{items.Length - 2})";

            _defs.TryGetValue("AllowedApplications", out var def);

            return new PolicySetting
            {
                Name = "AllowedApplications",
                DisplayName = def?.DisplayName ?? "Allowed Applications",
                RawValue = rawStr,
                InterpretedValue = items.Length == 0 ? "0 item(s)" : $"{items.Length} item(s) | {preview}",
                Description = def?.Description ?? "Allowed application patterns.",
                Severity = "Info"
            };
        }

        private IEnumerable<PolicySetting> ParseAsrPerRuleExclusions(object? raw)
        {
            var list = new List<PolicySetting>();
            var rawStr = raw?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(rawStr))
            {
                list.Add(new PolicySetting
                {
                    Name = "ASROnlyPerRuleExclusions",
                    DisplayName = "ASR Per-Rule Exclusions",
                    RawValue = rawStr,
                    InterpretedValue = "None",
                    Description = "No per-rule exclusions.",
                    Severity = "Info"
                });
                return list;
            }

            var segments = rawStr.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var seg in segments)
            {
                var idx = seg.IndexOf('=');
                if (idx <= 0) continue;
                var guidRaw = seg[..idx].Trim();
                var guid = guidRaw.ToUpperInvariant();
                var rest = seg[(idx + 1)..].Trim().Trim('"');
                var paths = rest.Split('>', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                string friendly = AsrRuleNames.TryGetValue(guid, out var fn) ? fn : guidRaw;
                string preview = string.Join(" > ", paths.Take(2));
                if (paths.Length > 2) preview += $" ... (+{paths.Length - 2})";
                list.Add(new PolicySetting
                {
                    Name = $"ASRExclusions:{guid}",
                    DisplayName = $"ASR Exclusions: {friendly}",
                    RawValue = rest,
                    InterpretedValue = $"{paths.Length} exclusion(s)",
                    Description = preview,
                    Severity = "Info"
                });
            }
            return list;
        }

        private IEnumerable<PolicySetting> ParseThreatSeverityDefaultAction(object? raw)
        {
            var list = new List<PolicySetting>();
            var rawStr = raw?.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(rawStr))
            {
                list.Add(new PolicySetting
                {
                    Name = "ThreatSeverityDefaultAction",
                    DisplayName = "Threat Severity Default Actions",
                    RawValue = rawStr,
                    InterpretedValue = "None",
                    Description = "No mappings set.",
                    Severity = "Info"
                });
                return list;
            }

            var pairs = rawStr.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var p in pairs)
            {
                var kv = p.Split('=', 2);
                if (kv.Length != 2) continue;
                var sev = kv[0].Trim();
                var act = kv[1].Trim();

                string sevName = sev switch
                {
                    "0" => "Unknown",
                    "1" => "Low",
                    "2" => "Moderate",
                    "4" => "High",
                    "5" => "Severe",
                    _ => $"Severity {sev}"
                };

                string actName = act switch
                {
                    "0" => "Allow",
                    "1" => "Clean",
                    "2" => "Quarantine",
                    "3" => "Remove",
                    "6" => "Block",
                    "8" => "Audit",
                    _ => $"Action {act}"
                };

                list.Add(new PolicySetting
                {
                    Name = $"ThreatAction:{sev}",
                    DisplayName = $"Threat Default: {sevName}",
                    RawValue = act,
                    InterpretedValue = actName,
                    Description = $"Default action for {sevName} threats.",
                    Severity = actName is "Allow" ? "Risk" : "Info"
                });
            }
            return list;
        }

        private static string MinutesToTime(int minutes)
        {
            if (minutes < 0 || minutes >= 1440) return minutes.ToString();
            var t = TimeSpan.FromMinutes(minutes);
            return t.ToString(@"hh\:mm");
        }
    }
}