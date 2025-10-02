using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Win32;

namespace MDE_Monitoring_App.Services
{
    public sealed class DeviceControlPolicyService
    {
        private const string RegistryBasePath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager";
        private const string GroupsValueName = "PolicyGroups";
        private const string RulesValueName  = "PolicyRules";

        internal static readonly Dictionary<string, string> _computerSidProfiles = new(StringComparer.OrdinalIgnoreCase)
        {
            ["S-1-12-1-3578890296-1131072958-874193792-1076261235"] = "Public",
            ["S-1-12-1-838819987-1132602012-1915727538-261826644"] = "Private",
            ["S-1-12-1-1499553166-1308696480-1828307335-3595922835"] = "DomainAuthenticated"
        };

        public async Task<DeviceControlPolicySnapshot> GetSnapshotAsync(
            string? fallbackGroupsFile = null,
            string? fallbackRulesFile  = null,
            CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();

                string? groupsXml = ReadRegistryString(GroupsValueName);
                string? rulesXml  = ReadRegistryString(RulesValueName);

                if (string.IsNullOrWhiteSpace(groupsXml) && !string.IsNullOrWhiteSpace(fallbackGroupsFile) && File.Exists(fallbackGroupsFile))
                    groupsXml = File.ReadAllText(fallbackGroupsFile);
                if (string.IsNullOrWhiteSpace(rulesXml) && !string.IsNullOrWhiteSpace(fallbackRulesFile) && File.Exists(fallbackRulesFile))
                    rulesXml = File.ReadAllText(fallbackRulesFile);

                var groups = ParseGroups(groupsXml);
                var rules  = ParseRules(rulesXml);

                var groupLookup = groups.ToDictionary(g => g.Id, StringComparer.OrdinalIgnoreCase);

                foreach (var rule in rules)
                {
                    rule.IncludedGroupsDisplay = string.Join(", ",
                        rule.IncludedGroupIds.Select(id => groupLookup.TryGetValue(id, out var g) ? g.DisplayNameOrId : id));
                    rule.ExcludedGroupsDisplay = string.Join(", ",
                        rule.ExcludedGroupIds.Select(id => groupLookup.TryGetValue(id, out var g) ? g.DisplayNameOrId : id));
                    rule.EntrySummary = SummarizeEntries(rule);
                }

                return new DeviceControlPolicySnapshot(groups, rules);
            }, ct).ConfigureAwait(false);
        }

        private static string SummarizeEntries(DeviceControlPolicyRule rule)
        {
            if (rule.Entries.Count == 0) return "None";

            var parts = rule.Entries
                .GroupBy(e => e.Type, StringComparer.OrdinalIgnoreCase)
                .Select(g => $"{g.Key}:{g.Count()}")
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var entrySids = rule.Entries
                .Select(e => e.Sid)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();
            if (entrySids.Count > 0)
                parts.Add("Sids: " + string.Join(", ", entrySids));

            var compSidLabels = rule.Entries
                .Select(e => e.ComputerSid)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => _computerSidProfiles.TryGetValue(s!, out var label) ? $"{s} ({label})" : s!)
                .Distinct()
                .ToList();
            if (compSidLabels.Count > 0)
                parts.Add("ComputerSids: " + string.Join(", ", compSidLabels));

            return string.Join(" | ", parts);
        }

        private static string? ReadRegistryString(string valueName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(RegistryBasePath, writable: false);
                if (key == null) return null;
                var obj = key.GetValue(valueName);
                return obj as string;
            }
            catch
            {
                return null;
            }
        }

        private static List<DeviceControlPolicyGroup> ParseGroups(string? xml)
        {
            var result = new List<DeviceControlPolicyGroup>();
            if (string.IsNullOrWhiteSpace(xml)) return result;

            try
            {
                using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
                {
                    IgnoreComments = true,
                    IgnoreWhitespace = true
                });

                DeviceControlPolicyGroup? current = null;
                string? currentElement = null;
                while (reader.Read())
                {
                    if (reader.NodeType == XmlNodeType.Element)
                    {
                        currentElement = reader.Name;
                        if (reader.Name.Equals("Group", StringComparison.OrdinalIgnoreCase))
                        {
                            var id = reader.GetAttribute("Id") ?? string.Empty;
                            current = new DeviceControlPolicyGroup(id);
                            result.Add(current);
                        }
                        else if (current != null && reader.IsEmptyElement == false)
                        {
                            if (reader.Name.Equals("VID_PID", StringComparison.OrdinalIgnoreCase) ||
                                reader.Name.Equals("PrimaryId", StringComparison.OrdinalIgnoreCase))
                            {
                                var val = reader.ReadElementContentAsString().Trim();
                                if (!string.IsNullOrEmpty(val))
                                    current.Descriptors.Add(val);
                                currentElement = null;
                            }
                        }
                    }
                    else if (reader.NodeType == XmlNodeType.Text && current != null && currentElement != null)
                    {
                        if (currentElement.Equals("MatchType", StringComparison.OrdinalIgnoreCase))
                            current.MatchType = reader.Value.Trim();
                    }
                }
            }
            catch
            {
            }

            return result;
        }

        private static List<DeviceControlPolicyRule> ParseRules(string? xml)
        {
            var result = new List<DeviceControlPolicyRule>();
            if (string.IsNullOrWhiteSpace(xml)) return result;

            try
            {
                using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
                {
                    IgnoreComments = true,
                    IgnoreWhitespace = true
                });

                DeviceControlPolicyRule? current = null;
                DeviceControlPolicyRuleEntry? currentEntry = null;
                string? currentElement = null;
                bool insideIncluded = false;
                bool insideExcluded = false;

                while (reader.Read())
                {
                    if (reader.NodeType == XmlNodeType.Element)
                    {
                        currentElement = reader.Name;

                        if (reader.Name.Equals("PolicyRule", StringComparison.OrdinalIgnoreCase))
                        {
                            var id = reader.GetAttribute("Id") ?? string.Empty;
                            current = new DeviceControlPolicyRule(id);
                            result.Add(current);
                        }
                        else if (current != null)
                        {
                            if (reader.Name.Equals("IncludedIdList", StringComparison.OrdinalIgnoreCase))
                            {
                                insideIncluded = true;
                                insideExcluded = false;
                            }
                            else if (reader.Name.Equals("ExcludedIdList", StringComparison.OrdinalIgnoreCase))
                            {
                                insideExcluded = true;
                                insideIncluded = false;
                            }
                            else if (reader.Name.Equals("GroupId", StringComparison.OrdinalIgnoreCase))
                            {
                                var gid = reader.ReadElementContentAsString().Trim();
                                if (!string.IsNullOrEmpty(gid))
                                {
                                    if (insideIncluded) current.IncludedGroupIds.Add(gid);
                                    else if (insideExcluded) current.ExcludedGroupIds.Add(gid);
                                }
                                currentElement = null;
                            }
                            else if (reader.Name.Equals("Entry", StringComparison.OrdinalIgnoreCase))
                            {
                                var eid = reader.GetAttribute("Id") ?? string.Empty;
                                currentEntry = new DeviceControlPolicyRuleEntry { Id = eid };
                                current.Entries.Add(currentEntry);
                            }
                        }
                    }
                    else if (reader.NodeType == XmlNodeType.Text)
                    {
                        if (current != null && currentElement != null)
                        {
                            if (currentElement.Equals("Name", StringComparison.OrdinalIgnoreCase))
                                current.Name = reader.Value.Trim();
                            else if (currentEntry != null)
                            {
                                switch (currentElement)
                                {
                                    case "Type":
                                        currentEntry.Type = reader.Value.Trim();
                                        break;
                                    case "AccessMask":
                                        if (ulong.TryParse(reader.Value.Trim(), out var mask))
                                            currentEntry.AccessMask = mask;
                                        else
                                            currentEntry.AccessMask = null;
                                        break;
                                    case "Options":
                                        if (uint.TryParse(reader.Value.Trim(), out var opt))
                                            currentEntry.Options = opt;
                                        else
                                            currentEntry.Options = null;
                                        break;
                                    case "Sid": // NEW
                                        currentEntry.Sid = reader.Value.Trim();
                                        break;
                                    case "ComputerSid":
                                        currentEntry.ComputerSid = reader.Value.Trim();
                                        break;
                                }
                            }
                        }
                    }
                    else if (reader.NodeType == XmlNodeType.EndElement)
                    {
                        if (reader.Name.Equals("IncludedIdList", StringComparison.OrdinalIgnoreCase))
                            insideIncluded = false;
                        else if (reader.Name.Equals("ExcludedIdList", StringComparison.OrdinalIgnoreCase))
                            insideExcluded = false;
                        else if (reader.Name.Equals("Entry", StringComparison.OrdinalIgnoreCase))
                            currentEntry = null;
                    }
                }
            }
            catch
            {
            }

            return result;
        }
    }

    public sealed record DeviceControlPolicySnapshot(
        IReadOnlyList<DeviceControlPolicyGroup> Groups,
        IReadOnlyList<DeviceControlPolicyRule> Rules);

    public sealed class DeviceControlPolicyGroup
    {
        public string Id { get; }
        public string MatchType { get; set; } = "";
        public List<string> Descriptors { get; } = new();
        public string DisplayNameOrId => Descriptors.Count > 0 ? $"{Id} ({string.Join(",", Descriptors.Take(3))}{(Descriptors.Count > 3 ? "..." : "")})" : Id;
        public DeviceControlPolicyGroup(string id) => Id = id;
    }

    public sealed class DeviceControlPolicyRule
    {
        public string Id { get; }
        public string Name { get; set; } = "";
        public List<string> IncludedGroupIds { get; } = new();
        public List<string> ExcludedGroupIds { get; } = new();
        public List<DeviceControlPolicyRuleEntry> Entries { get; } = new();
        public string IncludedGroupsDisplay { get; set; } = "";
        public string ExcludedGroupsDisplay { get; set; } = "";
        public string EntrySummary { get; set; } = "";

        // NEW display helpers for binding
        public string EntryTypesDisplay =>
            string.Join(Environment.NewLine, Entries.Select(e => e.Type).Where(t => !string.IsNullOrWhiteSpace(t)));

        public string EntryOptionsDisplay =>
            string.Join(Environment.NewLine, Entries.Select(e => e.Options?.ToString()).Where(s => !string.IsNullOrWhiteSpace(s)));

        // Collection so AccessMaskConverter can expand flags across entries
        public IEnumerable<ulong> EntryAccessMasks =>
            Entries.Where(e => e.AccessMask.HasValue).Select(e => e.AccessMask!.Value);

        public DeviceControlPolicyRule(string id) => Id = id;
    }

    public sealed class DeviceControlPolicyRuleEntry
    {
        public string Id { get; set; } = "";
        public string Type { get; set; } = "";
        public ulong? AccessMask { get; set; }
        public uint? Options { get; set; }
        public string? Sid { get; set; }          // NEW: User/Group SID (GUID style or security SID)
        public string? ComputerSid { get; set; }

        public string ComputerSidDisplay =>
            string.IsNullOrWhiteSpace(ComputerSid)
                ? ""
                : DeviceControlPolicyService._computerSidProfiles.TryGetValue(ComputerSid, out var profile)
                    ? $"{ComputerSid} ({profile})"
                    : ComputerSid;
    }

    public static class DeviceControlPolicyMappingExtensions
    {
        public static ObservableCollection<DeviceControlPolicyRule> ToObservable(this IEnumerable<DeviceControlPolicyRule> src) =>
            new(src);
        public static ObservableCollection<DeviceControlPolicyGroup> ToObservable(this IEnumerable<DeviceControlPolicyGroup> src) =>
            new(src);
    }
}