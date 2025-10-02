using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using MDE_Monitoring_App.Models;
using MDE_Monitoring_App.Services; // for WfpRuleNameCount

namespace MDE_Monitoring_App.Services
{
    public class PdfExportService
    {
        private const int MaxRowsPerSection = 150;

        static PdfExportService()
        {
            QuestPDF.Settings.License = LicenseType.Community;
        }

        public byte[] BuildReport(MainViewModel vm)
        {
            if (vm == null) throw new ArgumentNullException(nameof(vm));
            var snapshot = TakeSnapshot(vm);
            return Document(snapshot).GeneratePdf();
        }

        private static Snapshot TakeSnapshot(MainViewModel vm)
        {
            return new Snapshot
            {
                GeneratedUtc = DateTime.UtcNow,
                Defender = vm.DefenderStatus ?? new DefenderStatus(),
                LatestVersions = vm.LatestVersions,
                PlatformStatusText = vm.PlatformStatusText ?? string.Empty,
                EngineStatusText = vm.EngineStatusText ?? string.Empty,
                FirewallEvents = (vm.FirewallEvents ?? Enumerable.Empty<FirewallLogEntry>()).Take(MaxRowsPerSection).Where(e => e != null).ToList()!,
                DeviceControlEvents = (vm.DeviceControlEvents ?? new()).Take(MaxRowsPerSection).Where(e => e != null).ToList()!,
                Policies = (vm.DefenderPolicies ?? new()).Where(p => p != null).ToList()!,
                Logs = (vm.Logs ?? new()).Take(MaxRowsPerSection).Where(l => l != null).ToList()!,
                AppControlEvents = (vm.AppControlEvents ?? new()).Take(MaxRowsPerSection).Where(a => a != null).ToList()!,
                DeviceGuardStatus = vm.DeviceGuardStatus ?? new DeviceGuardStatus(),
                SystemInfo = vm.CurrentSystem ?? new SystemInfo(),
                IntuneLastSyncUtc = vm.IntuneLastSyncUtc,
                FirewallLoggingStatus = vm.FirewallLoggingStatusMessage ?? string.Empty,
                WfpFilterCount = vm.WfpFilterCount,
                WfpRuleCounts = vm.WfpRuleCounts?.ToList() ?? new()
            };
        }

        private static Document Document(Snapshot s) =>
            QuestPDF.Fluent.Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Margin(40);
                    page.Header().Element(c => Header(c, s));
                    page.Content().PaddingTop(10).Element(c => Body(c, s));
                    page.Footer().AlignCenter().Text(x =>
                    {
                        x.Span("Generated: ").SemiBold();
                        x.Span($"{s.GeneratedUtc:u} UTC  |  Page ");
                        x.CurrentPageNumber();
                        x.Span(" / ");
                        x.TotalPages();
                    });
                });
            });

        private static void Header(IContainer c, Snapshot s)
        {
            var sys = s.SystemInfo ?? new SystemInfo();
            c.Row(r =>
            {
                r.RelativeItem().Column(col =>
                {
                    col.Item().Text("MDE / Endpoint Security Summary").FontSize(18).SemiBold().FontColor(Colors.Blue.Medium);
                    col.Item().Text($"Machine: {sys.MachineName ?? ""}");
                    col.Item().Text($"User: {sys.CurrentUser ?? ""}");
                    col.Item().Text($"Platform: {s.PlatformStatusText}");
                    col.Item().Text($"Engine: {s.EngineStatusText}");
                });
                r.ConstantItem(120).AlignRight().Text(DateTime.Now.ToString("G")).FontSize(10);
            });
        }

        private static void Body(IContainer c, Snapshot s)
        {
            c.Column(col =>
            {
                var sys = s.SystemInfo ?? new SystemInfo();
                Section(col, "System Info", section =>
                {
                    section.Item().Text($"IP: {sys.IPAddress ?? ""}");
                    section.Item().Text($"Join Type: {sys.JoinType ?? ""}");
                });

                Section(col, "Defender Status", section =>
                {
                    var d = s.Defender ?? new DefenderStatus();
                    section.Item().Text($"Real-Time Protection: {d.RealTimeProtection}");
                    section.Item().Text($"Running Mode: {d.AMRunningMode}");
                    section.Item().Text($"AV Sig Age: {d.AntivirusSignatureAge}");
                    section.Item().Text($"AS Sig Age: {d.AntispywareSignatureAge}");
                    section.Item().Text($"Device Control Enforcement: {d.DeviceControlDefaultEnforcement}");
                    section.Item().Text($"Device Control State: {d.DeviceControlState}");
                    if (s.LatestVersions != null)
                    {
                        section.Item().Text($"Latest Platform Version: {s.LatestVersions.PlatformVersion}");
                        section.Item().Text($"Latest Engine Version: {s.LatestVersions.EngineVersion}");
                        section.Item().Text($"Latest Intelligence Version: {s.LatestVersions.SecurityIntelligenceVersion}");
                    }
                });

                var dg = s.DeviceGuardStatus ?? new DeviceGuardStatus();
                Section(col, "Device Guard / VBS", section =>
                {
                    section.Item().Text(dg.CodeIntegrityPolicyDisplay ?? "");
                    section.Item().Text(dg.VbsStatusDisplay ?? "");
                    section.Item().Text("Configured Services: " + (dg.SecurityServicesConfiguredDisplay ?? ""));
                    section.Item().Text("Running Services: " + (dg.SecurityServicesRunningDisplay ?? ""));
                });

                Section(col, "Intune / Entra Management", section =>
                {
                    section.Item().Text("Last Sync UTC: " + (s.IntuneLastSyncUtc?.ToString("u") ?? "Unknown"));
                });

                if (!string.IsNullOrWhiteSpace(s.FirewallLoggingStatus))
                {
                    Section(col, "Firewall Logging Advisory", section =>
                    {
                        section.Item().Text(s.FirewallLoggingStatus).FontColor(Colors.Orange.Darken2);
                    });
                }

                if (s.WfpFilterCount.HasValue)
                {
                    var count = s.WfpFilterCount.Value;
                    var noteColor = Colors.Black;
                    string text = $"Total WFP Filters: {count:N0}";
                    if (count >= 50000)
                    {
                        text += " (HIGH - consider pruning / investigating policy layering)";
                        noteColor = Colors.Red.Darken2;
                    }
                    else if (count >= 10000)
                    {
                        text += " (Large)";
                        noteColor = Colors.Orange.Darken2;
                    }

                    Section(col, "WFP Filters", section =>
                    {
                        section.Item().Text(text).FontColor(noteColor).SemiBold();

                        if (s.WfpRuleCounts != null && s.WfpRuleCounts.Count > 0)
                        {
                            var top = s.WfpRuleCounts.Take(15).ToList();
                            section.Item().PaddingTop(4).Text("Top Rule Names (by occurrence):").Italic().FontSize(10);
                            section.Item().Table(t =>
                            {
                                t.ColumnsDefinition(cd =>
                                {
                                    cd.RelativeColumn(3);
                                    cd.RelativeColumn(1);
                                });
                                t.Header(h =>
                                {
                                    h.Cell().Background(Colors.Grey.Lighten2).Padding(2).Text("Rule Name").SemiBold().FontSize(9);
                                    h.Cell().Background(Colors.Grey.Lighten2).Padding(2).AlignRight().Text("Count").SemiBold().FontSize(9);
                                });
                                foreach (var rc in top)
                                {
                                    t.Cell().Padding(2).Text(Shorten(rc.Name, 70)).FontSize(8);
                                    t.Cell().Padding(2).AlignRight().Text(rc.Count.ToString("N0")).FontSize(8);
                                }
                            });
                        }
                    });
                }

                TableSection(col, "Firewall Drops", s.FirewallEvents,
                    new[] { "Time", "Proto", "Src", "Dst", "SPort", "DPort", "Info" },
                    e => new[]
                    {
                        e?.Timestamp.ToString("HH:mm:ss") ?? "",
                        e?.Protocol ?? "",
                        e?.SourceIp ?? "",
                        e?.DestinationIp ?? "",
                        e?.SourcePort?.ToString() ?? "",
                        e?.DestinationPort?.ToString() ?? "",
                        e?.Info ?? ""
                    });

                TableSection(col, "Device Control Events", s.DeviceControlEvents,
                    new[] { "Time", "InstancePathId", "VID", "PID", "Denied", "Granted" },
                    e => new[]
                    {
                        e?.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                        e?.InstancePathId ?? "",
                        e?.VID ?? "",
                        e?.PID ?? "",
                        e?.DeniedAccess ?? "",
                        e?.GrantedAccess ?? ""
                    });

                TableSection(col, "App Control Events", s.AppControlEvents,
                    new[] { "Time", "ID", "Level", "Channel", "Message" },
                    e => new[]
                    {
                        e?.Time.ToString("HH:mm:ss") ?? "",
                        e?.Id.ToString() ?? "",
                        e?.Level ?? "",
                        Shorten(e?.Channel, 25),
                        Shorten(e?.Message, 80)
                    });

                TableSection(col, "Policies", s.Policies,
                    new[] { "Name", "Interpreted", "Raw", "Severity" },
                    p => (string[])(new[]
                    {
                        p?.DisplayName ?? "",
                        p?.InterpretedValue ?? "",
                        p?.RawValue ?? "",
                        p?.Severity ?? ""
                    }));

                TableSection(col, "Logs", s.Logs,
                    new[] { "Time", "Level", "Message" },
                    l => new[]
                    {
                        l?.Time.ToString("HH:mm:ss") ?? "",
                        l?.Level ?? "",
                        Shorten(l?.Message, 120)
                    });
            });
        }

        private static void Section(ColumnDescriptor col, string title, Action<ColumnDescriptor> content)
        {
            if (col == null) return;
            col.Item().PaddingBottom(6).Column(cc =>
            {
                cc.Item().Text(title ?? "").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                cc.Item().PaddingLeft(6).Column(content);
            });
        }

        private static void TableSection<T>(ColumnDescriptor col, string title, IList<T>? rows, string[] headers, Func<T, string[]> selector)
        {
            if (col == null || headers == null || selector == null) return;
            if (rows == null || rows.Count == 0) return;

            col.Item().PaddingBottom(8).Element(e =>
            {
                e.Column(cc =>
                {
                    cc.Item().Text(title ?? "").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                    cc.Item().Table(table =>
                    {
                        var hcount = headers.Length;
                        table.ColumnsDefinition(columns =>
                        {
                            columns.RelativeColumn();
                            for (int i = 0; i < hcount; i++)
                                columns.RelativeColumn();
                        });

                        table.Header(h =>
                        {
                            h.Cell().Background(Colors.Grey.Lighten2).Padding(2).Text("#").SemiBold().FontSize(9);
                            for (int i = 0; i < headers.Length; i++)
                                h.Cell().Background(Colors.Grey.Lighten2).Padding(2).Text(headers[i] ?? "").SemiBold().FontSize(9);
                        });

                        int idx = 1;
                        foreach (var row in rows.Where(r => r != null))
                        {
                            string[] cols;
                            try
                            {
                                cols = selector(row) ?? Array.Empty<string>();
                            }
                            catch
                            {
                                continue;
                            }

                            table.Cell().Padding(2).Text(idx++.ToString()).FontSize(8);
                            for (int i = 0; i < headers.Length; i++)
                            {
                                var cellText = i < cols.Length ? Shorten(cols[i], 90) : "";
                                table.Cell().Padding(2).Text(cellText ?? "").FontSize(8);
                            }
                        }
                    });
                });
            });
        }

        private static string Shorten(string? value, int max)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Length <= max ? value : value.Substring(0, max - 1) + "…";
        }

        private class Snapshot
        {
            public DateTime GeneratedUtc { get; set; }
            public DefenderStatus Defender { get; set; } = new();
            public LatestDefenderVersions? LatestVersions { get; set; }
            public string PlatformStatusText { get; set; } = "";
            public string EngineStatusText { get; set; } = "";
            public List<FirewallLogEntry> FirewallEvents { get; set; } = new();
            public List<DeviceControlEvent> DeviceControlEvents { get; set; } = new();
            public List<PolicySetting> Policies { get; set; } = new();
            public List<LogEntry> Logs { get; set; } = new();
            public List<AppControlEvent> AppControlEvents { get; set; } = new();
            public DeviceGuardStatus DeviceGuardStatus { get; set; } = new();
            public SystemInfo SystemInfo { get; set; } = new();
            public DateTime? IntuneLastSyncUtc { get; set; }
            public string FirewallLoggingStatus { get; set; } = "";
            public int? WfpFilterCount { get; set; }
            public List<WfpRuleNameCount> WfpRuleCounts { get; set; } = new();
        }
    }
}