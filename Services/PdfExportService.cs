using MDE_Monitoring_App.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

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
            return QuestPDF.Fluent.GenerateExtensions.GeneratePdf(BuildDocument(snapshot) as QuestPDF.Infrastructure.IDocument);
        }

        private static Snapshot TakeSnapshot(MainViewModel vm) => new()
        {
            GeneratedUtc = DateTime.UtcNow,
            Defender = vm.DefenderStatus ?? new(),
            LatestVersions = vm.LatestVersions,
            PlatformStatusText = vm.PlatformStatusText ?? "",
            EngineStatusText = vm.EngineStatusText ?? "",
            PlatformUpToDate = vm.PlatformUpToDate,
            EngineUpToDate = vm.EngineUpToDate,
            LatestFetchState = vm.LatestFetchState,
            LatestFetchError = vm.LatestFetchError ?? "",
            FirewallEvents = (vm.FirewallEvents != null ? vm.FirewallEvents : new ObservableCollection<FirewallLogEntry>()).Take(MaxRowsPerSection).ToList(),
            DeviceControlEvents = (vm.DeviceControlEvents ?? new()).Take(MaxRowsPerSection).ToList(),
            Policies = (vm.DefenderPolicies ?? new()).Take(MaxRowsPerSection).ToList(),
            Logs = (vm.Logs ?? new()).Take(MaxRowsPerSection).ToList(),
            AppControlEvents = (vm.AppControlEvents ?? new()).Take(MaxRowsPerSection).ToList(),
            AppControlStatus = vm.AppControlStatus ?? new(),
            DeviceGuardStatus = vm.DeviceGuardStatus ?? new(),
            SystemInfo = vm.CurrentSystem ?? new(),
            IntuneLastSyncUtc = vm.IntuneLastSyncUtc,
            IntuneEnrollmentStatus = vm.IntuneEnrollmentStatus,
            IntuneEnrollmentUpn = vm.IntuneEnrollmentUpn,
            IntuneEnrollmentState = vm.IntuneEnrollmentState,
            FirewallLoggingStatus = vm.FirewallLoggingStatusMessage ?? "",
            FirewallProfilesMultiline = vm.FirewallProfilesMultilineDisplay ?? "",
            DeviceControlPolicyStatus = vm.DeviceControlPolicyStatus ?? "",
            DeviceControlPolicyGroupsCount = vm.DeviceControlPolicyGroups?.Count ?? 0,
            DeviceControlPolicyRulesCount = vm.DeviceControlPolicyRules?.Count ?? 0,
            WfpFilterCount = vm.WfpFilterCount,
            WfpRuleCounts = vm.WfpRuleCounts?.ToList() ?? new(),
            WfpModeDiagnostics = vm.WfpModeDiagnostics ?? "",
            WfpRemoteStatusNote = vm.WfpRemoteStatusNote ?? "",
            IsRemote = vm.IsRemote,
            TargetMachine = vm.TargetMachine,
            RemoteCapabilityStatus = RemoteCapabilityStatusCache ?? "",
            WfpDiagnostics = !vm.WfpFilterCount.HasValue ? "WFP summary unavailable (permission / remote limitation)." : null,
            TamperProtectionDisplay = vm.DefenderStatus?.TamperProtectionDisplay ?? "Tamper Protection: Unknown"
        };

        private static QuestPDF.Infrastructure.IDocument BuildDocument(Snapshot s) =>
            QuestPDF.Fluent.Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Margin(40);
                    page.Header().Element(c => RenderHeader(c, s));
                    page.Content().PaddingTop(10).Element(c => RenderBody(c, s));
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

        private static void RenderHeader(IContainer c, Snapshot s)
        {
            var sys = s.SystemInfo ?? new SystemInfo();
            c.Row(r =>
            {
                r.RelativeItem().Column(col =>
                {
                    col.Item().Text("Endpoint Security Summary").FontSize(18).SemiBold().FontColor(Colors.Blue.Medium);
                    col.Item().Text($"Source: {(s.IsRemote ? "Remote" : "Local")}{(s.IsRemote ? $" ({s.TargetMachine})" : "")}");
                    col.Item().Text($"Machine: {sys.MachineName}");
                    col.Item().Text($"User: {sys.CurrentUser}");
                    col.Item().Text($"Platform: {s.PlatformStatusText}");
                    col.Item().Text($"Engine: {s.EngineStatusText}");
                    col.Item().Text($"Version Fetch State: {s.LatestFetchState}{(string.IsNullOrWhiteSpace(s.LatestFetchError) ? "" : $" (Error: {Shorten(s.LatestFetchError, 60)})")}")
                        .FontSize(9).FontColor(Colors.Grey.Darken2);
                    col.Item().Text($"Remote Capability: {(s.IsRemote ? s.RemoteCapabilityStatus : "Local Full")}").FontSize(9);
                });
                r.ConstantItem(140).AlignRight().Text(DateTime.Now.ToString("G")).FontSize(10);
            });
        }

        private static void RenderBody(IContainer c, Snapshot s)
        {
            c.Column(col =>
            {
                Section(col, "System Info", sec =>
                {
                    sec.Item().Text($"IP: {s.SystemInfo?.IPAddress ?? ""}");
                    sec.Item().Text($"Join Type: {s.SystemInfo?.JoinType ?? ""}");
                    if (s.IsRemote)
                        sec.Item().Text("Remote Collection: Windows integrated credentials").FontColor(Colors.Green.Darken2).FontSize(10);
                });

                Section(col, "Defender Status", sec =>
                {
                    var d = s.Defender;
                    sec.Item().Text($"Product Version: {d.AMProductVersion}");
                    sec.Item().Text($"Engine Version: {d.AMEngineVersion}");
                    sec.Item().Text($"Real-Time Protection: {d.RealTimeProtection}");
                    sec.Item().Text($"Running Mode: {d.AMRunningMode}");
                    sec.Item().Text($"AV Sig Age: {d.AntivirusSignatureAge}");
                    sec.Item().Text($"AS Sig Age: {d.AntispywareSignatureAge}");
                    sec.Item().Text($"Device Control Enforcement: {d.DeviceControlDefaultEnforcementDisplay}");
                    sec.Item().Text($"Device Control State: {d.DeviceControlState}");
                    sec.Item().Text(s.TamperProtectionDisplay);
                    if (s.LatestVersions != null)
                    {
                        sec.Item().Text($"Latest Platform: {s.LatestVersions.PlatformVersion} (UpToDate: {s.PlatformUpToDate})");
                        sec.Item().Text($"Latest Engine: {s.LatestVersions.EngineVersion} (UpToDate: {s.EngineUpToDate})");
                        sec.Item().Text($"Latest Intelligence: {s.LatestVersions.SecurityIntelligenceVersion}");
                    }
                });

                Section(col, "Device Guard / VBS", sec =>
                {
                    var dg = s.DeviceGuardStatus;
                    sec.Item().Text(dg.CodeIntegrityPolicyDisplay ?? "");
                    sec.Item().Text(dg.VbsStatusDisplay ?? "");
                    sec.Item().Text("Configured Services: " + (dg.SecurityServicesConfiguredDisplay ?? ""));
                    sec.Item().Text("Running Services: " + (dg.SecurityServicesRunningDisplay ?? ""));
                    sec.Item().Text("User-mode CI: " + (dg.UsermodeCodeIntegrityPolicyDisplay ?? ""));
                    sec.Item().Text("Security Features Enabled: " + (dg.SecurityFeaturesEnabledDisplay ?? ""));
                });

                Section(col, "App Control Status", sec =>
                {
                    sec.Item().Text($"Kernel Mode CI: {s.AppControlStatus.KernelModeCodeIntegrity}");
                    sec.Item().Text($"User Mode CI: {s.AppControlStatus.UserModeCodeIntegrity}");
                });

                Section(col, "Intune / Entra Enrollment", sec =>
                {
                    sec.Item().Text("Last Sync UTC: " + (s.IntuneLastSyncUtc?.ToString("u") ?? "Unknown"));
                    sec.Item().Text("Enrollment Type: " + s.IntuneEnrollmentStatus);
                    sec.Item().Text("Enrollment State: " + s.IntuneEnrollmentState);
                    sec.Item().Text("UPN: " + s.IntuneEnrollmentUpn);
                });

                Section(col, "Firewall Profiles", sec =>
                {
                    if (!string.IsNullOrWhiteSpace(s.FirewallProfilesMultiline))
                        sec.Item().Text(s.FirewallProfilesMultiline).FontSize(9).FontFamily("Consolas");
                    else
                        sec.Item().Text("No firewall profile data.");
                    if (!string.IsNullOrWhiteSpace(s.FirewallLoggingStatus))
                        sec.Item().Text("Logging Advisory: " + s.FirewallLoggingStatus).FontColor(Colors.Orange.Darken2);
                });

                Section(col, "Device Control Policy Summary", sec =>
                {
                    sec.Item().Text($"Status: {s.DeviceControlPolicyStatus}");
                    sec.Item().Text($"Groups: {s.DeviceControlPolicyGroupsCount} | Rules: {s.DeviceControlPolicyRulesCount}");
                });

                if (s.WfpFilterCount.HasValue)
                {
                    Section(col, "WFP Filters", sec =>
                    {
                        var count = s.WfpFilterCount.Value;
                        var text = $"Total Filters: {count:N0}";
                        var color = Colors.Black;
                        if (count >= 50000) { text += " (HIGH)"; color = Colors.Red.Darken2; }
                        else if (count >= 10000) { text += " (Large)"; color = Colors.Orange.Darken2; }
                        sec.Item().Text(text).SemiBold().FontColor(color);
                        if (!string.IsNullOrWhiteSpace(s.WfpRemoteStatusNote))
                            sec.Item().Text("Remote Note: " + s.WfpRemoteStatusNote).FontSize(9).FontColor(Colors.Grey.Darken2);
                        if (!string.IsNullOrWhiteSpace(s.WfpModeDiagnostics))
                            sec.Item().Text("Mode Diagnostics: " + s.WfpModeDiagnostics).FontSize(9);
                        if (s.WfpRuleCounts.Any())
                        {
                            var top = s.WfpRuleCounts.Take(20).ToList();
                            sec.Item().Text("Top Rule Names:").Italic().FontSize(10);
                            sec.Item().Table(t =>
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
                                    t.Cell().Padding(2).Text(Shorten(rc.Name, 80)).FontSize(8);
                                    t.Cell().Padding(2).AlignRight().Text(rc.Count.ToString("N0")).FontSize(8);
                                }
                            });
                        }
                    });
                }
                else
                {
                    Section(col, "WFP Filters", sec =>
                    {
                        sec.Item().Text(s.WfpDiagnostics ?? "No WFP data").FontColor(Colors.Grey.Darken2);
                        if (!string.IsNullOrWhiteSpace(s.WfpRemoteStatusNote))
                            sec.Item().Text("Remote Note: " + s.WfpRemoteStatusNote).FontSize(9).FontColor(Colors.Grey.Darken2);
                    });
                }

                Section(col, "Collection Notes", sec =>
                {
                    sec.Item().Text(s.IsRemote
                        ? "Remote collection may omit certain detailed WFP and live Defender runtime attributes due to protocol limitations."
                        : "Local collection includes full detail set.")
                        .FontSize(9).FontColor(Colors.Grey.Darken2);
                });

                TableSection(col, "Firewall Drops", s.FirewallEvents,
                    new[] { "Time", "Proto", "Src", "Dst", "SPort", "DPort", "Info" },
                    e => new[]
                    {
                        e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        e.Protocol,
                        e.SourceIp,
                        e.DestinationIp,
                        e.SourcePort?.ToString() ?? "",
                        e.DestinationPort?.ToString() ?? "",
                        e.Info
                    });

                TableSection(col, "Device Control Events", s.DeviceControlEvents,
                    new[] { "Time", "InstancePathId", "VID", "PID", "Denied", "Granted" },
                    e => new[]
                    {
                        e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        e.InstancePathId ?? "",
                        e.VID ?? "",
                        e.PID ?? "",
                        e.DeniedAccess ?? "",
                        e.GrantedAccess ?? ""
                    });

                TableSection(col, "App Control Events", s.AppControlEvents,
                    new[] { "Time", "ID", "Level", "Channel", "Message" },
                    e => new[]
                    {
                        e.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                        e.Id.ToString(),
                        e.Level,
                        e.Channel,
                        e.Message
                    });

                TableSection(col, "Policies", s.Policies,
                    new[] { "Name", "Interpreted", "Raw", "Severity" },
                    p => new[]
                    {
        p.DisplayName,
        p.InterpretedValue,
        p.RawValue?.ToString(),
        p.Severity
                    });

                TableSection(col, "Defender Logs", s.Logs,
                    new[] { "Time", "Level", "Message" },
                    l => new[]
                    {
                        l.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                        l.Level,
                        l.Message
                    });
            });
        }

        private static void Section(ColumnDescriptor col, string title, Action<ColumnDescriptor> content)
        {
            col.Item().PaddingBottom(6).Column(cc =>
            {
                cc.Item().Text(title).FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                cc.Item().PaddingLeft(6).Column(content);
            });
        }

        private static void TableSection<T>(ColumnDescriptor col, string title, IList<T>? rows, string[] headers, Func<T, string[]> selector)
        {
            if (rows == null || rows.Count == 0) return;
            col.Item().PaddingBottom(8).Element(e =>
            {
                e.Column(cc =>
                {
                    cc.Item().Text(title).FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                    cc.Item().Table(table =>
                    {
                        table.ColumnsDefinition(def =>
                        {
                            def.ConstantColumn(22);
                            foreach (var _ in headers) def.RelativeColumn();
                        });

                        table.Header(h =>
                        {
                            h.Cell().Background(Colors.Grey.Lighten2).Padding(2).Text("#").SemiBold().FontSize(9);
                            foreach (var hdr in headers)
                                h.Cell().Background(Colors.Grey.Lighten2).Padding(2).Text(hdr).SemiBold().FontSize(9);
                        });

                        int i = 1;
                        foreach (var row in rows)
                        {
                            string[] cols;
                            try { cols = selector(row) ?? Array.Empty<string>(); }
                            catch { continue; }

                            table.Cell().Padding(2).Text(i++.ToString()).FontSize(8);
                            for (int c = 0; c < headers.Length; c++)
                            {
                                var cellText = c < cols.Length ? Shorten(cols[c], 95) : "";
                                table.Cell().Padding(2).Text(cellText).FontSize(8);
                            }
                        }
                    });
                });
            });
        }

        private static string Shorten(string? value, int max) =>
            string.IsNullOrEmpty(value) ? "" : (value.Length <= max ? value : value.Substring(0, max - 1) + "…");

        private class Snapshot
        {
            public DateTime GeneratedUtc { get; set; }
            public DefenderStatus Defender { get; set; } = new();
            public LatestDefenderVersions? LatestVersions { get; set; }
            public string PlatformStatusText { get; set; } = "";
            public string EngineStatusText { get; set; } = "";
            public bool PlatformUpToDate { get; set; }
            public bool EngineUpToDate { get; set; }
            public LatestFetchState LatestFetchState { get; set; }
            public string LatestFetchError { get; set; } = "";
            public List<FirewallLogEntry> FirewallEvents { get; set; } = new();
            public List<DeviceControlEvent> DeviceControlEvents { get; set; } = new();
            public List<PolicySetting> Policies { get; set; } = new();
            public List<LogEntry> Logs { get; set; } = new();
            public List<AppControlEvent> AppControlEvents { get; set; } = new();
            public AppControlStatus AppControlStatus { get; set; } = new();
            public DeviceGuardStatus DeviceGuardStatus { get; set; } = new();
            public SystemInfo SystemInfo { get; set; } = new();
            public DateTime? IntuneLastSyncUtc { get; set; }
            public string IntuneEnrollmentStatus { get; set; } = "";
            public string IntuneEnrollmentUpn { get; set; } = "";
            public string IntuneEnrollmentState { get; set; } = "";
            public string FirewallLoggingStatus { get; set; } = "";
            public string FirewallProfilesMultiline { get; set; } = "";
            public string DeviceControlPolicyStatus { get; set; } = "";
            public int DeviceControlPolicyGroupsCount { get; set; }
            public int DeviceControlPolicyRulesCount { get; set; }
            public int? WfpFilterCount { get; set; }
            public List<WfpRuleNameCount> WfpRuleCounts { get; set; } = new();
            public string WfpModeDiagnostics { get; set; } = "";
            public string WfpRemoteStatusNote { get; set; } = "";
            public bool IsRemote { get; set; }
            public string? TargetMachine { get; set; }
            public string RemoteCapabilityStatus { get; set; } = "";
            public string? WfpDiagnostics { get; set; }
            public string TamperProtectionDisplay { get; set; } = "";
        }

        public static string? RemoteCapabilityStatusCache { get; private set; }
        public static void UpdateRemoteCapabilityStatus(string? val) => RemoteCapabilityStatusCache = val;
    }
}