using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace MDE_Monitoring_App.Services
{
    public enum WfpFilterCountMode
    {
        UniqueFilterIds,              // Distinct <filterId>
        AllNameElements,              // Every <name> under an <item>
        LegacyDoubleNameHeuristic,    // (direct <item>/<name>) + first <displayData>/<name> if both exist
        PowerShellEmulation           // Legacy buggy PowerShell logic: counts only every 2nd <name> (kept for comparison)
    }

    public record WfpRuleNameCount(string Name, int Count);

    public record WfpFilterSummary
    {
        public long TotalFilterCount { get; init; }
        public long DistinctRuleNames => RuleCounts?.Count ?? 0;
        public double? FileSizeMb { get; init; }
        public string? SourceFilePath { get; init; }
        public string? ModeDiagnostics { get; init; }
        public List<WfpRuleNameCount> RuleCounts { get; init; } = new();
        public WfpFilterCountMode Mode { get; init; }
    }

    public class WfpFilterService
    {
        private readonly WfpFilterCountMode _mode;
        private readonly bool _preserveXml;

        public WfpFilterService(
            WfpFilterCountMode mode = WfpFilterCountMode.UniqueFilterIds,
            bool preserveXmlForDebug = false)
        {
            _mode = mode;
            _preserveXml = preserveXmlForDebug;
        }

        public async Task<WfpFilterSummary?> GetFilterSummaryAsync(
            bool includeRuleCounts = true,
            CancellationToken ct = default)
        {
            try
            {
                var baseDir = Path.Combine(Path.GetTempPath(), "MDEMonitor", "Wfp");
                Directory.CreateDirectory(baseDir);
                var xmlPath = Path.Combine(baseDir, $"wfp_filters_{Guid.NewGuid():N}.xml");

                if (!await RunNetshAsync(xmlPath, ct).ConfigureAwait(false))
                    return null;
                if (!File.Exists(xmlPath))
                    return null;

                WfpFilterSummary parsed = _mode switch
                {
                    WfpFilterCountMode.PowerShellEmulation      => ParsePowerShellEmulation(xmlPath, includeRuleCounts, ct),
                    WfpFilterCountMode.AllNameElements          => ParseAllNameElements(xmlPath, includeRuleCounts, ct),
                    WfpFilterCountMode.LegacyDoubleNameHeuristic=> ParseLegacyDoubleName(xmlPath, includeRuleCounts, ct),
                    _                                           => ParseUniqueFilterIds(xmlPath, includeRuleCounts, ct)
                };

                // Augment with raw quick counts for diagnostics
                var rawFilterIdOccurrences = QuickCount(xmlPath, "<filterId>");
                var rawNameOccurrences     = QuickCount(xmlPath, "<name>");

                string diag = $"Mode={_mode}; ParsedTotal={parsed.TotalFilterCount}; Raw<filterId>Occurrences={rawFilterIdOccurrences}; Raw<name>Occurrences={rawNameOccurrences}; " +
                              $"DistinctRuleNames={parsed.DistinctRuleNames}";

                // If suspiciously low (e.g., <= 25 while raw counts indicate hundreds), give hint
                if (parsed.TotalFilterCount <= 25 && (rawFilterIdOccurrences > 100 || rawNameOccurrences > 100))
                    diag += " | Warning: parsed total very low vs raw occurrences (elevation? XML shape?).";

                try
                {
                    var fi = new FileInfo(xmlPath);
                    if (fi.Exists)
                        parsed = parsed with { FileSizeMb = fi.Length / (1024d * 1024d) };
                }
                catch { }

                if (_preserveXml)
                    parsed = parsed with { SourceFilePath = xmlPath };
                else
                    TryDelete(xmlPath);

                parsed = parsed with { ModeDiagnostics = diag };
                return parsed;
            }
            catch
            {
                return null;
            }
        }

        // Mode: UniqueFilterIds (one per distinct <filterId>, first name captured if appears before or after)
        private WfpFilterSummary ParseUniqueFilterIds(string path, bool includeNames, CancellationToken ct)
        {
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;

            bool insideItem = false;
            string? currentId = null;
            string? firstName = null;

            using var reader = CreateReader(path);
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                    {
                        insideItem = true;
                        currentId = null;
                        firstName = null;
                    }
                    else if (insideItem && reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                    {
                        if (firstName == null)
                        {
                            var nm = SafeReadElementString(reader).Trim();
                            if (!string.IsNullOrEmpty(nm))
                                firstName = nm;
                        }
                        else
                            _ = SafeReadElementString(reader); // consume additional
                    }
                    else if (insideItem && reader.Name.Equals("filterId", StringComparison.OrdinalIgnoreCase))
                    {
                        var fid = SafeReadElementString(reader).Trim();
                        if (!string.IsNullOrEmpty(fid) && ids.Add(fid) && includeNames)
                            Increment(names, firstName ?? "(Unnamed)");
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement &&
                         reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                {
                    insideItem = false;
                }
            }

            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.UniqueFilterIds,
                TotalFilterCount = ids.Count,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        // Mode: AllNameElements
        private WfpFilterSummary ParseAllNameElements(string path, bool includeNames, CancellationToken ct)
        {
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;
            long total = 0;

            using var reader = CreateReader(path);
            bool insideItem = false;
            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                        insideItem = true;
                    else if (insideItem && reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                    {
                        var nm = SafeReadElementString(reader).Trim();
                        if (!string.IsNullOrEmpty(nm))
                        {
                            total++;
                            if (includeNames) Increment(names, nm);
                        }
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement &&
                         reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                {
                    insideItem = false;
                }
            }

            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.AllNameElements,
                TotalFilterCount = total,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        // Mode: LegacyDoubleNameHeuristic
        // Count: (direct <item>/<name>) + (first <displayData>/<name>) if both exist per filter
        private WfpFilterSummary ParseLegacyDoubleName(string path, bool includeNames, CancellationToken ct)
        {
            long total = 0;
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;

            using var reader = CreateReader(path);
            bool insideItem = false;
            bool haveDirectName = false;
            bool haveDisplayName = false;
            string? directName = null;
            string? displayName = null;

            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();

                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                    {
                        insideItem = true;
                        haveDirectName = false;
                        haveDisplayName = false;
                        directName = null;
                        displayName = null;
                    }
                    else if (insideItem && reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                    {
                        // Heuristic: first <name> before any <displayData> treat as directName
                        var nm = SafeReadElementString(reader).Trim();
                        if (!string.IsNullOrEmpty(nm))
                        {
                            if (!haveDirectName && !haveDisplayName)
                            {
                                directName = nm;
                                haveDirectName = true;
                                total++;
                                if (includeNames) Increment(names, nm);
                            }
                            else if (!haveDisplayName)
                            {
                                displayName = nm;
                                haveDisplayName = true;
                                total++;
                                if (includeNames) Increment(names, nm);
                            }
                            // further names ignored
                        }
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement &&
                         reader.Name.Equals("item", StringComparison.OrdinalIgnoreCase))
                {
                    insideItem = false;
                }
            }

            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.LegacyDoubleNameHeuristic,
                TotalFilterCount = total,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        // Mode: PowerShellEmulation (deprecated)
        // Intentionally reproduces the legacy PowerShell bug:
        // For each <name> encountered, jumps to the NEXT <name> and counts that one.
        // This yields roughly half of the real <name> count.
        private WfpFilterSummary ParsePowerShellEmulation(string path, bool includeNames, CancellationToken ct)
        {
            Dictionary<string, int>? names = includeNames ? new(StringComparer.OrdinalIgnoreCase) : null;
            using var reader = CreateReader(path);
            long total = 0;

            while (reader.Read())
            {
                ct.ThrowIfCancellationRequested();
                if (reader.NodeType == XmlNodeType.Element &&
                    reader.Name.Equals("name", StringComparison.OrdinalIgnoreCase))
                {
                    var nm = SafeReadElementString(reader).Trim();
                    if (!string.IsNullOrEmpty(nm))
                    {
                        total++;
                        if (includeNames) Increment(names, nm);
                    }
                }
            }

            return new WfpFilterSummary
            {
                Mode = WfpFilterCountMode.PowerShellEmulation,
                TotalFilterCount = total,
                RuleCounts = names != null ? ToSorted(names) : new()
            };
        }

        private async Task<bool> RunNetshAsync(string xmlPath, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"wfp show filters file=\"{xmlPath}\" verbose=on",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return false;
            _ = proc.StandardOutput.ReadToEndAsync();
            _ = proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            return proc.ExitCode == 0;
        }

        private static XmlReader CreateReader(string path) =>
            XmlReader.Create(File.OpenRead(path), new XmlReaderSettings
            {
                IgnoreComments = true,
                IgnoreWhitespace = true,
                DtdProcessing = DtdProcessing.Ignore
            });

        private static string SafeReadElementString(XmlReader reader)
        {
            try { return reader.ReadElementContentAsString(); }
            catch { return string.Empty; }
        }

        private static void Increment(Dictionary<string, int>? dict, string key)
        {
            if (dict == null) return;
            if (dict.TryGetValue(key, out var c))
                dict[key] = c + 1;
            else
                dict[key] = 1;
        }

        private static long QuickCount(string path, string token)
        {
            long count = 0;
            using var sr = new StreamReader(path);
            string? line;
            while ((line = sr.ReadLine()) != null)
                if (line.Contains(token, StringComparison.OrdinalIgnoreCase))
                    count++;
            return count;
        }

        private static List<WfpRuleNameCount> ToSorted(Dictionary<string, int> dict)
        {
            var list = new List<WfpRuleNameCount>(dict.Count);
            foreach (var kv in dict)
                list.Add(new WfpRuleNameCount(kv.Key, kv.Value));
            list.Sort((a, b) => b.Count.CompareTo(a.Count));
            return list;
        }

        private void TryDelete(string path)
        {
            try { File.Delete(path); } catch { }
        }
    }
}