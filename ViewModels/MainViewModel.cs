using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows.Data;
using MDE_Monitoring_App.Models;
using MDE_Monitoring_App.Services;
using System.IO;
using System.Threading;
using System.Text;
using System.Text.Json; // ADD

namespace MDE_Monitoring_App
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private readonly DefenderStatusService _defenderStatusService = new();
        private readonly LogCollector _logCollector = new();
        private readonly FirewallLogService _firewallLogService = new();
        private readonly DefenderPolicyService _policyService = new();
        private readonly LatestDefenderVersionService _latestVersionService = new();
        private readonly IntuneSyncService _intuneSyncService = new();
        private readonly AppControlStatusService _appControlStatusService = new();
        private readonly AppControlLogService _appControlLogService = new();
        private readonly DeviceGuardStatusService _deviceGuardStatusService = new();
        private readonly WfpFilterService _wfpFilterService = new(WfpFilterCountMode.LegacyDoubleNameHeuristic, preserveXmlForDebug: true);
        private readonly DeviceControlPolicyService _deviceControlPolicyService = new();
        private readonly FirewallStatusService _firewallStatusService = new();
        private readonly RemoteSystemInfoService _remoteSystemInfoService = new();
        private readonly IntuneEnrollmentService _intuneEnrollmentService = new();


        public ObservableCollection<LogEntry> Logs { get; } = new();
        public ObservableCollection<DeviceControlPolicyGroup>? DeviceControlPolicyGroups { get; private set; }
        public ObservableCollection<DeviceControlPolicyRule>? DeviceControlPolicyRules { get; private set; }
        private ObservableCollection<DeviceControlEvent> _deviceControlEvents = new();
        public ObservableCollection<DeviceControlEvent> DeviceControlEvents
        {
            get => _deviceControlEvents;
            private set { if (value != _deviceControlEvents) { _deviceControlEvents = value; OnPropertyChanged(); } }
        }

        public ObservableCollection<FirewallLogEntry> FirewallEvents { get; } = new();
        public ObservableCollection<PolicySetting> DefenderPolicies { get; } = new();
        public ObservableCollection<AppControlEvent> AppControlEvents { get; } = new();
        public ObservableCollection<WfpRuleNameCount> WfpRuleCounts { get; } = new();

        private string? _deviceControlPolicyStatus = "Not loaded";
        public string? DeviceControlPolicyStatus
        {
            get => _deviceControlPolicyStatus;
            set { if (_deviceControlPolicyStatus != value) { _deviceControlPolicyStatus = value; OnPropertyChanged(); } }
        }

        public ICollectionView LogsView { get; }
        public ICollectionView FirewallView { get; }
        public ICollectionView PolicyView { get; }
        public DefenderStatus DefenderStatus { get; } = new();
        public Models.SystemInfo CurrentSystem { get; } = new();

        private DateTime _lastRefreshed;
        public DateTime LastRefreshed
        {
            get => _lastRefreshed;
            private set
            {
                if (_lastRefreshed != value)
                {
                    _lastRefreshed = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(LastRefreshedDisplay));
                }
            }
        }
        public string LastRefreshedDisplay => LastRefreshed.ToString("G");

        private string _logFilter = "All";
        public string LogFilter
        {
            get => _logFilter;
            set
            {
                if (_logFilter != value)
                {
                    _logFilter = value;
                    OnPropertyChanged();
                    LogsView.Refresh();
                }
            }
        }

        private int _logTimeRangeHours = 1;
        public int LogTimeRangeHours
        {
            get => _logTimeRangeHours;
            set
            {
                if (value == _logTimeRangeHours) return;
                _logTimeRangeHours = value;
                OnPropertyChanged();
                LogsView.Refresh();
            }
        }

        private string _firewallFilterText = string.Empty;
        public string FirewallFilterText
        {
            get => _firewallFilterText;
            set
            {
                if (_firewallFilterText != value)
                {
                    _firewallFilterText = value;
                    OnPropertyChanged();
                    FirewallView.Refresh();
                }
            }
        }

        private LatestDefenderVersions? _latestVersions;
        public LatestDefenderVersions? LatestVersions
        {
            get => _latestVersions;
            private set
            {
                if (_latestVersions != value)
                {
                    _latestVersions = value;
                    OnPropertyChanged();
                    RaiseVersionProps();
                }
            }
        }

        private string _platformStatusText = "Unknown";
        private string _engineStatusText = "Unknown";

        public string PlatformStatusText
        {
            get => _platformStatusText;
            set
            {
                var computed = BuildStatusText(DefenderStatus.AMProductVersion, LatestVersions?.PlatformVersion, PlatformUpToDate);
                if (_platformStatusText != computed)
                {
                    _platformStatusText = computed;
                    OnPropertyChanged();
                }
            }
        }

        public string EngineStatusText
        {
            get => _engineStatusText;
            set
            {
                var computed = BuildStatusText(DefenderStatus.AMEngineVersion, LatestVersions?.EngineVersion, EngineUpToDate);
                if (_engineStatusText != computed)
                {
                    _engineStatusText = computed;
                    OnPropertyChanged();
                }
            }
        }

        public bool PlatformUpToDate => IsUpToDate(DefenderStatus.AMProductVersion, LatestVersions?.PlatformVersion);
        public bool EngineUpToDate => IsUpToDate(DefenderStatus.AMEngineVersion, LatestVersions?.EngineVersion);

        private void RaiseVersionProps()
        {
            var newPlat = BuildStatusText(DefenderStatus.AMProductVersion, LatestVersions?.PlatformVersion, PlatformUpToDate);
            var newEng = BuildStatusText(DefenderStatus.AMEngineVersion, LatestVersions?.EngineVersion, EngineUpToDate);

            if (_platformStatusText != newPlat)
            {
                _platformStatusText = newPlat;
                OnPropertyChanged(nameof(PlatformStatusText));
            }
            if (_engineStatusText != newEng)
            {
                _engineStatusText = newEng;
                OnPropertyChanged(nameof(EngineStatusText));
            }

            OnPropertyChanged(nameof(PlatformUpToDate));
            OnPropertyChanged(nameof(EngineUpToDate));
        }

        private static bool IsUpToDate(string? local, string? latest)
        {
            if (string.IsNullOrWhiteSpace(local) || string.IsNullOrWhiteSpace(latest)) return true;
            if (!Version.TryParse(Normalize(local), out var lv)) return true;
            if (!Version.TryParse(Normalize(latest), out var rv)) return true;
            return lv >= rv;
        }

        private static string BuildStatusText(string? local, string? latest, bool upToDate)
        {
            if (string.IsNullOrWhiteSpace(local)) return "Unknown";
            if (latest == null || latest.Length == 0)
                return local + " (Unavailable)";
            if (upToDate) return $"{local} (Up to date)";
            return $"{local} (Out of date → Latest {latest})";
        }

        private static string Normalize(string v) => v.Trim();

        public MainViewModel()
        {
            LogsView = CollectionViewSource.GetDefaultView(Logs);
            LogsView.Filter = LogFilterPredicate;

            FirewallView = CollectionViewSource.GetDefaultView(FirewallEvents);
            FirewallView.Filter = FirewallFilter;

            PolicyView = CollectionViewSource.GetDefaultView(DefenderPolicies);

            DefenderStatus.PropertyChanged += DefenderStatusOnPropertyChanged;

            // Initialize remote execution defaults
            UsePsExec = false;                // default to WinRM
            PsExecPath = @"C:\Sysinternals\PsExec.exe";

            LoadCompliancePolicy(); // LOAD POLICY EARLY

            _ = RefreshDataAsync();
        }

        private void DefenderStatusOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(DefenderStatus.AMProductVersion) ||
                e.PropertyName == nameof(DefenderStatus.AMEngineVersion))
            {
                RaiseVersionProps();
            }
        }

        private bool LogFilterPredicate(object obj)
        {
            if (obj is not LogEntry entry) return false;
            var cutoff = DateTime.Now.AddHours(-LogTimeRangeHours);
            if (entry.Time < cutoff) return false;
            if (LogFilter == "All") return true;
            return string.Equals(entry.Level, LogFilter, StringComparison.OrdinalIgnoreCase);
        }

        public void ReplaceLogs(IEnumerable<LogEntry> newLogs)
        {
            Logs.Clear();
            foreach (var l in newLogs)
                Logs.Add(l);
            LastRefreshed = DateTime.Now;
            OnPropertyChanged(nameof(LastRefreshed));
            LogsView.Refresh();
        }

        private bool FirewallFilter(object obj)
        {
            if (string.IsNullOrWhiteSpace(FirewallFilterText)) return true;
            if (obj is not FirewallLogEntry e) return false;

            var term = FirewallFilterText.Trim();
            var cmp = StringComparison.OrdinalIgnoreCase;

            return
                (e.Action?.Contains(term, cmp) ?? false) ||
                (e.Protocol?.Contains(term, cmp) ?? false) ||
                (e.SourceIp?.Contains(term, cmp) ?? false) ||
                (e.DestinationIp?.Contains(term, cmp) ?? false) ||
                (e.SourcePort?.ToString()?.Contains(term, cmp) ?? false) ||
                (e.DestinationPort?.ToString()?.Contains(term, cmp) ?? false) ||
                (e.Size?.ToString()?.Contains(term, cmp) ?? false) ||
                (e.Info?.Contains(term, cmp) ?? false) ||
                (e.Path?.Contains(term, cmp) ?? false) ||
                (e.Pid?.ToString()?.Contains(term, cmp) ?? false);
        }

        private LatestFetchState _latestFetchState = LatestFetchState.Pending;
        public LatestFetchState LatestFetchState
        {
            get => _latestFetchState;
            private set
            {
                if (_latestFetchState != value)
                {
                    _latestFetchState = value;
                    OnPropertyChanged();
                    RaiseVersionProps();
                }
            }
        }

        private string? _latestFetchError;
        public string? LatestFetchError
        {
            get => _latestFetchError;
            private set { if (_latestFetchError != value) { _latestFetchError = value; OnPropertyChanged(); } }
        }

        private DateTime? _intuneLastSyncUtc;
        public DateTime? IntuneLastSyncUtc
        {
            get => _intuneLastSyncUtc;
            private set
            {
                if (_intuneLastSyncUtc != value)
                {
                    _intuneLastSyncUtc = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IntuneLastSyncLocalDisplay));
                    OnPropertyChanged(nameof(IntuneLastSyncUtcDisplay));
                }
            }
        }

        public string IntuneLastSyncLocalDisplay
        {
            get => _intuneLastSyncUtc.HasValue ? _intuneLastSyncUtc.Value.ToLocalTime().ToString("G") : "Unknown";
            set { }
        }

        public string IntuneLastSyncUtcDisplay
        {
            get => _intuneLastSyncUtc.HasValue ? _intuneLastSyncUtc.Value.ToString("u") : "Unknown";
            set { }
        }

        private DeviceGuardStatus _deviceGuardStatus = new();
        public DeviceGuardStatus DeviceGuardStatus
        {
            get => _deviceGuardStatus;
            private set
            {
                _deviceGuardStatus = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CodeIntegrityPolicyDisplay));
                OnPropertyChanged(nameof(VbsStatusDisplay));
                OnPropertyChanged(nameof(SecurityServicesConfiguredDisplay));
                OnPropertyChanged(nameof(SecurityServicesRunningDisplay));
                OnPropertyChanged(nameof(AvailableSecurityPropertiesDisplay));
                OnPropertyChanged(nameof(RequiredSecurityPropertiesDisplay));
                OnPropertyChanged(nameof(SecurityFeaturesEnabledDisplay));
                OnPropertyChanged(nameof(UsermodeCodeIntegrityPolicyDisplay));
                OnPropertyChanged(nameof(InstanceIdentifierDisplay));
                OnPropertyChanged(nameof(VersionDisplay));
            }
        }

        public string CodeIntegrityPolicyDisplay => "Code Integrity Policy: " + DeviceGuardStatus.CodeIntegrityPolicyDisplay;
        public string VbsStatusDisplay => "VBS Status: " + DeviceGuardStatus.VbsStatusDisplay;
        public string SecurityServicesConfiguredDisplay => "Configured Services: " + DeviceGuardStatus.SecurityServicesConfiguredDisplay;
        public string SecurityServicesRunningDisplay => "Running Services: " + DeviceGuardStatus.SecurityServicesRunningDisplay;
        public string AvailableSecurityPropertiesDisplay => "Available: " + DeviceGuardStatus.AvailableSecurityPropertiesDisplay;
        public string RequiredSecurityPropertiesDisplay => "Required: " + DeviceGuardStatus.RequiredSecurityPropertiesDisplay;
        public string SecurityFeaturesEnabledDisplay => "Features Enabled: " + DeviceGuardStatus.SecurityFeaturesEnabledDisplay;
        public string UsermodeCodeIntegrityPolicyDisplay => "User-mode CI: " + DeviceGuardStatus.UsermodeCodeIntegrityPolicyDisplay;
        public string InstanceIdentifierDisplay => "Instance ID: " + DeviceGuardStatus.InstanceIdentifierDisplay;
        public string VersionDisplay => "Schema Version: " + DeviceGuardStatus.VersionDisplay;

        private async Task<DeviceGuardStatus> LoadDeviceGuardStatusAsync()
        {
            await Task.Delay(500).ConfigureAwait(false);
            return new DeviceGuardStatus
            {
                CodeIntegrityPolicyEnforcementStatus = 1,
                VirtualizationBasedSecurityStatus = 1,
                SecurityServicesConfigured = new uint[] { 1 },
                SecurityServicesRunning = new uint[] { 1 },
            };
        }

        private int? _wfpFilterCount;
        public int? WfpFilterCount
        {
            get => _wfpFilterCount;
            set
            {
                if (value == _wfpFilterCount) return;
                _wfpFilterCount = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(WfpFilterCountStatus));
                OnPropertyChanged(nameof(WfpFilterCountTooltip));
            }
        }

        private string? _wfpModeDiagnostics;
        public string? WfpModeDiagnostics
        {
            get => _wfpModeDiagnostics;
            private set { if (_wfpModeDiagnostics != value) { _wfpModeDiagnostics = value; OnPropertyChanged(); } }
        }

        private string? _wfpRemoteStatusNote;
        public string? WfpRemoteStatusNote
        {
            get => _wfpRemoteStatusNote;
            private set { if (_wfpRemoteStatusNote != value) { _wfpRemoteStatusNote = value; OnPropertyChanged(); } }
        }

        public string WfpFilterCountStatus
        {
            get
            {
                if (!WfpFilterCount.HasValue) return "Unknown";
                if (WfpFilterCount.Value >= 50000) return "High";
                if (WfpFilterCount.Value >= 10000) return "Large";
                return "Normal";
            }
        }

        public string WfpFilterCountTooltip =>
            WfpFilterCountStatus switch
            {
                "High" => ">= 50,000 filters: potential performance / manageability impact.",
                "Large" => ">= 30,000 filters: elevated count – monitor growth.",
                "Normal" => "Filter count within typical range.",
                _ => "Filter count not available."
            };

        private IReadOnlyList<FirewallProfileStatus> _firewallProfileStatusesDisplay = Array.Empty<FirewallProfileStatus>();
        public IReadOnlyList<FirewallProfileStatus> FirewallProfileStatusesDisplay
        {
            get => _firewallProfileStatusesDisplay;
            private set
            {
                _firewallProfileStatusesDisplay = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FirewallProfilesDisplay));
                OnPropertyChanged(nameof(FirewallProfilesMultilineDisplay));
            }
        }

        public string FirewallProfilesDisplay
        {
            get
            {
                if (FirewallProfileStatusesDisplay.Count == 0) return "Firewall: Unknown";
                return string.Join(" | ", FirewallProfileStatusesDisplay);
            }
        }

        public string FirewallProfilesMultilineDisplay
        {
            get
            {
                if (FirewallProfileStatusesDisplay.Count == 0) return "Firewall: Unknown";
                var order = new[] { "Domain", "Private", "Public" };
                var profiles = FirewallProfileStatusesDisplay
                    .OrderBy(p => Array.IndexOf(order, p.Profile) switch { -1 => 999, var idx => idx })
                    .ThenBy(p => p.Profile, StringComparer.OrdinalIgnoreCase);

                var sb = new StringBuilder();
                sb.Append("Firewall Profiles:");
                foreach (var p in profiles)
                {
                    sb.AppendLine();
                    sb.Append("  ")
                      .Append(p.Profile.PadRight(7))
                      .Append(" : ")
                      .Append(p.Enabled ? "On " : "Off")
                      .Append("  In:")
                      .Append(p.InboundPolicy)
                      .Append("  Out:")
                      .Append(p.OutboundPolicy);
                }
                return sb.ToString();
            }
        }

        private string _targetMachine = "localhost";
        public string TargetMachine
        {
            get => _targetMachine;
            set
            {
                var normalized = string.IsNullOrWhiteSpace(value) ? "localhost" : value.Trim();
                if (!string.Equals(_targetMachine, normalized, StringComparison.OrdinalIgnoreCase))
                {
                    _targetMachine = normalized;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsRemote));
                    OnPropertyChanged(nameof(TargetMachineStatus));
                }
            }
        }

        private static bool IsLocalHostName(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return true;
            var h = value.Trim().ToLowerInvariant();
            if (h is "localhost" or "." or "127.0.0.1" or "::1") return true;
            var local = Environment.MachineName.ToLowerInvariant();
            if (h == local) return true;
            try
            {
                var dns = System.Net.Dns.GetHostName().ToLowerInvariant();
                if (h == dns) return true;
                var full = System.Net.Dns.GetHostEntry(dns).HostName.ToLowerInvariant();
                if (h == full) return true;
            }
            catch { }
            return false;
        }

        public bool IsRemote => !IsLocalHostName(TargetMachine);

        public string TargetMachineStatus => IsRemote ? $"Remote: {TargetMachine}" : "Local";

        private bool _isBusy;
        public bool IsBusy
        {
            get => _isBusy;
            private set
            {
                if (_isBusy != value)
                {
                    _isBusy = value;
                    OnPropertyChanged();
                }
            }
        }


        public async Task RefreshDataAsync()
        {
            if (IsBusy) return;
            IsBusy = true;
            try
            {
                using var refreshCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var remoteOpts = BuildRemoteOptions();

                var dcTask = Task.Run(() => DeviceControlService.LoadLatestDeviceControlEvents(IsRemote ? TargetMachine : null, 500, refreshCts.Token), refreshCts.Token);
                var logsTask = Task.Run(() => _logCollector.GetDefenderLogs(IsRemote ? TargetMachine : null, remoteOpts, refreshCts.Token), refreshCts.Token);
                var statusTask = Task.Run(() => _defenderStatusService.GetStatus(IsRemote ? TargetMachine : null, remoteOpts?.LongTimeout ?? TimeSpan.FromSeconds(5)), refreshCts.Token);
                var firewallTask = Task.Run(() => _firewallLogService.LoadRecentDrops(200, IsRemote ? TargetMachine : null, refreshCts.Token), refreshCts.Token);
                _wfpFilterService.UsePsExecFallback = UsePsExec;
                _wfpFilterService.PsExecCustomPath = string.IsNullOrWhiteSpace(PsExecPath) ? null : PsExecPath;
                var wfpTask = _wfpFilterService.GetFilterSummarySafeAsync(
                    IsRemote ? TargetMachine : null,
                    includeRuleCounts: true,
                    ct: refreshCts.Token,
                    timeout: remoteOpts?.LongTimeout ?? TimeSpan.FromSeconds(25));
                _policyService.UsePsExec = UsePsExec;
                _policyService.PsExecCustomPath = string.IsNullOrWhiteSpace(PsExecPath) ? null : PsExecPath;
                var policyTask = Task.Run(() => _policyService.LoadPolicies(IsRemote ? TargetMachine : null), refreshCts.Token);
                var latestTask = _latestVersionService.GetLatestAsync();
                var intuneSyncTask = Task.Run(_intuneSyncService.GetLastSync, refreshCts.Token);
                var appControlStatusTask = Task.Run(_appControlStatusService.GetStatus, refreshCts.Token);
                var appControlLogsTask = Task.Run(() => _appControlLogService.GetRecent(IsRemote ? TargetMachine : null, 150, refreshCts.Token, remoteOpts?.ShortTimeout ?? TimeSpan.FromSeconds(8), remoteOpts), refreshCts.Token);
                _deviceGuardStatusService.UsePsExecFallback = UsePsExec;
                _deviceGuardStatusService.PsExecCustomPath = string.IsNullOrWhiteSpace(PsExecPath) ? null : PsExecPath;
                var dgTask = _deviceGuardStatusService.GetStatusAsync(
                    IsRemote ? TargetMachine : null,
                    TimeSpan.FromSeconds(20),
                    refreshCts.Token);
                DeviceControlPolicyStatus = "Loading...";
                var dcPoliciesTask = _deviceControlPolicyService.GetSnapshotAsync(
                    fallbackGroupsFile: "SamplePolicies/PolicyGroups.txt",
                    fallbackRulesFile: "SamplePolicies/PolicyRules.txt",
                    ct: refreshCts.Token,
                    targetMachine: IsRemote ? TargetMachine : null);
                var fwStatusTask = Task.Run(() => _firewallStatusService.GetStatus(IsRemote ? TargetMachine : null, TimeSpan.FromSeconds(12), refreshCts.Token), refreshCts.Token);
                var enrollmentTask = Task.Run(() => _intuneEnrollmentService.Get(IsRemote ? TargetMachine : null), refreshCts.Token);

                // Await
                var dcEvents = await dcTask.ConfigureAwait(false);
                var newLogs = await logsTask.ConfigureAwait(false);
                var newStatus = await statusTask.ConfigureAwait(false);
                var fwEvents = await firewallTask.ConfigureAwait(false);
                var wfpSummary = await wfpTask.ConfigureAwait(false);
                var policies = await policyTask.ConfigureAwait(false);
                var latest = await latestTask.ConfigureAwait(false);
                var intuneLastSync = await intuneSyncTask.ConfigureAwait(false);
                var appControlStatus = await appControlStatusTask.ConfigureAwait(false);
                var appControlLogs = await appControlLogsTask.ConfigureAwait(false);
                var deviceGuardStatus = await dgTask.ConfigureAwait(false);
                var dcPoliciesSnapshot = await dcPoliciesTask.ConfigureAwait(false);
                var fwProfiles = await fwStatusTask.ConfigureAwait(false);
                var enrollmentInfo = await enrollmentTask.ConfigureAwait(false);

                if (IsRemote)
                {
                    var caps = new List<string>
                    {
                        "DefenderStatus:" + (string.IsNullOrWhiteSpace(newStatus?.AMProductVersion) ? "FAIL" : "OK"),
                        "Policies:"       + (policies?.Any() == true ? "OK" : "FAIL"),
                        "DeviceControlPolicy:" + (dcPoliciesSnapshot?.Rules?.Any() == true ? "OK" : "FAIL"),
                        "DefenderLogs:"   + (newLogs?.Any() == true ? "OK" : "FAIL"),
                        "AppControlLogs:" + (appControlLogs?.Any() == true ? "OK" : "FAIL"),
                        "FirewallDrops:"  + (fwEvents?.Any() == true ? "OK" : "FAIL"),
                        "WFP:"            + ((wfpSummary?.TotalFilterCount ?? 0) > 0 ? "OK" : "EMPTY")
                    };
                    if (!string.IsNullOrEmpty(wfpSummary?.RemoteStatusNote))
                        caps.Add("WFPNote:" + wfpSummary.RemoteStatusNote);
                    RemoteCapabilityStatus = string.Join(" | ", caps);
                }
                else
                {
                    RemoteCapabilityStatus = "Local Full";
                }

                App.Current.Dispatcher.Invoke(() =>
                {
                    DeviceControlEvents = new(dcEvents);

                    Logs.Clear();
                    foreach (var l in newLogs) Logs.Add(l);

                    FirewallEvents.Clear();
                    foreach (var f in fwEvents) FirewallEvents.Add(f);
                    FirewallView.Refresh();

                    DefenderPolicies.Clear();
                    foreach (var p in policies) DefenderPolicies.Add(p);
                    PolicyView.Refresh();

                    DefenderStatus.AMProductVersion = newStatus.AMProductVersion;
                    DefenderStatus.AMEngineVersion = newStatus.AMEngineVersion;
                    DefenderStatus.AMRunningMode = newStatus.AMRunningMode;
                    DefenderStatus.RealTimeProtection = newStatus.RealTimeProtection;
                    DefenderStatus.AntivirusSignatureAge = newStatus.AntivirusSignatureAge;
                    DefenderStatus.AntispywareSignatureAge = newStatus.AntispywareSignatureAge;
                    DefenderStatus.DeviceControlDefaultEnforcement = newStatus.DeviceControlDefaultEnforcement;
                    DefenderStatus.DeviceControlState = newStatus.DeviceControlState;
                    DefenderStatus.IsTamperProtected = newStatus.IsTamperProtected;
                    DefenderStatus.CloudProtection = newStatus.CloudProtection;
                    DefenderStatus.SampleSubmission = newStatus.SampleSubmission;
                    DefenderStatus.IoavProtection = newStatus.IoavProtection;
                    DefenderStatus.OnAccessProtection = newStatus.OnAccessProtection;
                    DefenderStatus.SmartAppControl = newStatus.SmartAppControl;
                    // ADD THESE TWO LINES TO SURFACE WMI SCAN AGE VALUES
                    DefenderStatus.FullScanAgeDays = newStatus.FullScanAgeDays;
                    DefenderStatus.QuickScanAgeDays = newStatus.QuickScanAgeDays;

                    if (IsRemote)
                    {
                        try
                        {
                            var remoteInfo = _remoteSystemInfoService.Get(TargetMachine, TimeSpan.FromSeconds(6), refreshCts.Token);
                            CurrentSystem.MachineName = remoteInfo.MachineName;
                            CurrentSystem.IPAddress = remoteInfo.IPAddress;
                            CurrentSystem.JoinType = remoteInfo.JoinType;
                            CurrentSystem.CurrentUser = remoteInfo.CurrentUser;
                        }
                        catch
                        {
                            CurrentSystem.MachineName = TargetMachine;
                            CurrentSystem.IPAddress = "RemoteError";
                            CurrentSystem.JoinType = "Unknown";
                            CurrentSystem.CurrentUser = "Unknown";
                        }
                    }
                    else
                    {
                        CurrentSystem.CurrentUser = Environment.UserName;
                        CurrentSystem.MachineName = Environment.MachineName;
                        CurrentSystem.IPAddress = GetLocalIPAddress();
                        CurrentSystem.JoinType = GetAADJoinType();
                    }

                    LatestVersions = latest.versions;
                    LatestFetchState = latest.state;
                    LatestFetchError = latest.error;
                    IntuneLastSyncUtc = intuneLastSync;
                    _intuneEnrollmentInfo = enrollmentInfo;
                    OnPropertyChanged(nameof(IntuneEnrollmentStatus));
                    OnPropertyChanged(nameof(IntuneEnrollmentEffectiveType));
                    OnPropertyChanged(nameof(IntuneEnrollmentOrigin));
                    OnPropertyChanged(nameof(IntuneEnrollmentUpn));
                    OnPropertyChanged(nameof(IntuneEnrollmentState));
                    OnPropertyChanged(nameof(IsIntuneCoManaged));
                    OnPropertyChanged(nameof(IntuneEnrollmentDisplay));

                    AppControlStatus = appControlStatus;

                    AppControlEvents.Clear();
                    foreach (var ev in appControlLogs) AppControlEvents.Add(ev);

                    DeviceGuardStatus = deviceGuardStatus;

                    if (wfpSummary != null)
                    {
                        WfpFilterCount = (int?)wfpSummary.TotalFilterCount;
                        WfpRuleCounts.Clear();
                        foreach (var rc in wfpSummary.RuleCounts)
                            WfpRuleCounts.Add(rc);
                        WfpModeDiagnostics = wfpSummary.ModeDiagnostics;
                        WfpRemoteStatusNote = wfpSummary.RemoteStatusNote;
                    }
                    else
                    {
                        WfpFilterCount = null;
                        WfpRuleCounts.Clear();
                        WfpModeDiagnostics = "No data";
                        WfpRemoteStatusNote = null;
                    }

                    if (fwProfiles.Count > 0)
                        FirewallProfileStatusesDisplay = fwProfiles;
                    else
                        FirewallProfileStatusesDisplay = Array.Empty<FirewallProfileStatus>();

                    if (dcPoliciesSnapshot != null)
                    {
                        DeviceControlPolicyGroups = new ObservableCollection<DeviceControlPolicyGroup>(dcPoliciesSnapshot.Groups);
                        DeviceControlPolicyRules = new ObservableCollection<DeviceControlPolicyRule>(dcPoliciesSnapshot.Rules);
                        OnPropertyChanged(nameof(DeviceControlPolicyGroups));
                        OnPropertyChanged(nameof(DeviceControlPolicyRules));
                        DeviceControlPolicyStatus = $"Groups: {dcPoliciesSnapshot.Groups.Count} | Rules: {dcPoliciesSnapshot.Rules.Count}";
                    }
                    else
                    {
                        DeviceControlPolicyStatus = "No policy data";
                    }
                    PdfExportService.UpdateRemoteCapabilityStatus(RemoteCapabilityStatus);

                    LastRefreshed = DateTime.Now;
                    LogsView.Refresh();

                    EvaluateCompliance();
                });
            }
            catch (Exception ex)
            {
                App.Current.Dispatcher.Invoke(() =>
                {
                    Logs.Insert(0, new LogEntry
                    {
                        Time = DateTime.Now,
                        Level = "Error",
                        Message = $"Failed to refresh: {ex.Message}"
                    });
                    DeviceControlPolicyStatus = "Failed to load";
                    RemoteCapabilityStatus = IsRemote ? "Remote refresh failed" : "Local refresh failed";
                    PdfExportService.UpdateRemoteCapabilityStatus(RemoteCapabilityStatus);
                });
            }
            finally
            {
                IsBusy = false;
            }
        }

        private string GetLocalIPAddress()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            return addr.Address.ToString();
                    }
                }
            }
            catch { }
            return "Unknown";
        }

        private string GetAADJoinType()
        {
            try
            {
                var psi = new ProcessStartInfo("dsregcmd.exe", "/status")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return "Unknown";
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                bool aad = output.Contains("AzureAdJoined : YES");
                bool domain = output.Contains("DomainJoined : YES");
                if (aad && domain) return "Hybrid Azure AD Join";
                if (aad) return "Azure AD Joined";
                if (domain) return "Domain Joined";
                return "Workgroup";
            }
            catch { return "Unknown"; }
        }

        public IReadOnlyList<FirewallLogService.FirewallProfileLogStatus> FirewallProfileStatuses
        {
            get => _firewallProfileStatuses;
            private set
            {
                _firewallProfileStatuses = value;
                OnPropertyChanged();
                UpdateFirewallLoggingStatusMessage();
            }
        }
        private IReadOnlyList<FirewallLogService.FirewallProfileLogStatus> _firewallProfileStatuses =
            Array.Empty<FirewallLogService.FirewallProfileLogStatus>();

        public string FirewallLoggingStatusMessage
        {
            get => _firewallLoggingStatusMessage;
            private set
            {
                if (_firewallLoggingStatusMessage != value)
                {
                    _firewallLoggingStatusMessage = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(ShowFirewallLoggingStatusMessage));
                }
            }
        }
        private string _firewallLoggingStatusMessage = string.Empty;
        private AppControlStatus _appControlStatus = new();

        public bool ShowFirewallLoggingStatusMessage => !string.IsNullOrEmpty(FirewallLoggingStatusMessage);
        public AppControlStatus AppControlStatus
        {
            get => _appControlStatus;
            private set
            {
                if (_appControlStatus != value)
                {
                    _appControlStatus = value;
                    OnPropertyChanged();
                }
            }
        }
        private void UpdateFirewallLoggingStatusMessage()
        {
            if (FirewallProfileStatuses.Count == 0)
            {
                FirewallLoggingStatusMessage = "No firewall profiles detected.";
                return;
            }

            var noDropped = FirewallProfileStatuses.Where(p => !p.LogDropped).Select(p => p.Profile).ToList();
            var noAllowed = FirewallProfileStatuses.Where(p => !p.LogAllowed).Select(p => p.Profile).ToList();

            if (!noDropped.Any() && !noAllowed.Any())
            {
                FirewallLoggingStatusMessage = string.Empty;
                return;
            }

            var parts = new System.Collections.Generic.List<string>();
            if (noDropped.Any())
                parts.Add("Dropped packet logging disabled for: " + string.Join(", ", noDropped));
            if (noAllowed.Any())
                parts.Add("Allowed connection logging disabled for: " + string.Join(", ", noAllowed));

            parts.Add("Enable with (example):");
            parts.Add("  netsh advfirewall set allprofiles logging droppedconnections enable");
            parts.Add("  netsh advfirewall set allprofiles logging allowedconnections enable");

            FirewallLoggingStatusMessage = string.Join(Environment.NewLine, parts);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        public async Task<bool> ExportPdfAsync(string filePath, CancellationToken ct = default)
        {
            try
            {
                var exporter = new PdfExportService();
                var bytes = await Task.Run(() => exporter.BuildReport(this), ct).ConfigureAwait(false);
                await File.WriteAllBytesAsync(filePath, bytes, ct).ConfigureAwait(false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private string _remoteUser = "";
        public string RemoteUser
        {
            get => _remoteUser;
            set { if (_remoteUser != value) { _remoteUser = value.Trim(); OnPropertyChanged(); } }
        }
        private string _remoteDomain = "";
        public string RemoteDomain
        {
            get => _remoteDomain;
            set { if (_remoteDomain != value) { _remoteDomain = value.Trim(); OnPropertyChanged(); } }
        }
        private System.Security.SecureString? _remotePassword;
        public void SetRemotePassword(System.Security.SecureString? pwd)
        {
            _remotePassword = pwd;
            OnPropertyChanged(nameof(RemotePasswordSet));
        }
        public bool RemotePasswordSet => _remotePassword != null && _remotePassword.Length > 0;

        private string _remoteCapabilityStatus = "";
        public string RemoteCapabilityStatus
        {
            get => _remoteCapabilityStatus;
            private set { if (_remoteCapabilityStatus != value) { _remoteCapabilityStatus = value; OnPropertyChanged(); } }
        }

        // NEW: PsExec toggle + path (default path)
        private bool _usePsExec;
        public bool UsePsExec
        {
            get => _usePsExec;
            set
            {
                if (_usePsExec != value)
                {
                    _usePsExec = value;
                    _wfpFilterService.UsePsExecFallback = value; // propagate to service
                    OnPropertyChanged();
                }
            }
        }

        private string _psExecPath = @"C:\Sysinternals\PsExec.exe";
        public string PsExecPath
        {
            get => _psExecPath;
            set
            {
                var norm = string.IsNullOrWhiteSpace(value) ? @"C:\Sysinternals\PsExec.exe" : value.Trim();
                if (_psExecPath != norm)
                {
                    _psExecPath = norm;
                    _wfpFilterService.PsExecCustomPath = norm; // propagate to service
                    OnPropertyChanged();
                }
            }
        }

        // Helper object passed to services
        private RemoteAccessOptions? BuildRemoteOptions()
        {
            if (!IsRemote) return null;
            return new RemoteAccessOptions(TargetMachine, RemoteDomain, RemoteUser, _remotePassword,
                TimeSpan.FromSeconds(6), TimeSpan.FromSeconds(10));
        }

        public record RemoteAccessOptions(
            string Host,
            string? Domain,
            string? User,
            System.Security.SecureString? Password,
            TimeSpan ShortTimeout,
            TimeSpan LongTimeout);

        private IntuneEnrollmentInfo _intuneEnrollmentInfo = new();
        public string IntuneEnrollmentStatus => _intuneEnrollmentInfo.Type;
        public string IntuneEnrollmentEffectiveType => _intuneEnrollmentInfo.EffectiveType;
        public string IntuneEnrollmentOrigin => _intuneEnrollmentInfo.EnrollmentOrigin;
        public string IntuneEnrollmentUpn => _intuneEnrollmentInfo.UPN;
        public string IntuneEnrollmentState => _intuneEnrollmentInfo.EnrollmentStateDisplay;
        public bool IsIntuneCoManaged => _intuneEnrollmentInfo.IsCoManaged;

        // Updated combined display to use derived values
        public string IntuneEnrollmentDisplay =>
            $"{IntuneEnrollmentEffectiveType} | {IntuneEnrollmentOrigin} | UPN: {IntuneEnrollmentUpn} | State: {IntuneEnrollmentState}";

        // --- Compliance additions ---
        private CompliancePolicy? _compliancePolicy;
        public ObservableCollection<ComplianceItem> ComplianceItems { get; } = new();

        private double _compliancePercentage;
        public double CompliancePercentage
        {
            get => _compliancePercentage;
            private set
            {
                if (Math.Abs(_compliancePercentage - value) > 0.0001)
                {
                    _compliancePercentage = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(ComplianceSummaryDisplay));
                }
            }
        }

        public string ComplianceSummaryDisplay =>
            ComplianceItems.Count == 0
                ? "No compliance items"
                : $"{CompliancePercentage:0}% compliant ({ComplianceItems.Count(c => c.Compliant)}/{ComplianceItems.Count})";

        public string CompliancePolicyName => _compliancePolicy?.Name ?? "(none)";
        public string CompliancePolicyDescription => _compliancePolicy?.Description ?? "No compliance policy loaded.";
        // ADD: Combined header for UI
        public string CompliancePolicyHeader => $"{CompliancePolicyName} - {CompliancePolicyDescription}";

        public void LoadCompliancePolicy()
        {
            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, "CompliancePolicy.config.json");
                if (!File.Exists(path))
                {
                    _compliancePolicy = null;
                    OnPropertyChanged(nameof(CompliancePolicyName));
                    OnPropertyChanged(nameof(CompliancePolicyDescription));
                    OnPropertyChanged(nameof(CompliancePolicyHeader)); // ADD
                    ComplianceItems.Clear();
                    CompliancePercentage = 0;
                    return;
                }
                var json = File.ReadAllText(path);
                _compliancePolicy = JsonSerializer.Deserialize<CompliancePolicy>(json);
                OnPropertyChanged(nameof(CompliancePolicyName));
                OnPropertyChanged(nameof(CompliancePolicyDescription));
                OnPropertyChanged(nameof(CompliancePolicyHeader)); // ADD
            }
            catch (Exception ex)
            {
                Logs.Insert(0, new LogEntry
                {
                    Time = DateTime.Now,
                    Level = "Error",
                    Message = "Failed to load compliance policy: " + ex.Message
                });
                _compliancePolicy = null;
                OnPropertyChanged(nameof(CompliancePolicyName));
                OnPropertyChanged(nameof(CompliancePolicyDescription));
                OnPropertyChanged(nameof(CompliancePolicyHeader)); // ADD
            }
            EvaluateCompliance();
        }

        public void EvaluateCompliance()
        {
            ComplianceItems.Clear();
            if (_compliancePolicy == null)
            {
                CompliancePercentage = 0;
                OnPropertyChanged(nameof(ComplianceSummaryDisplay));
                return;
            }

            bool IsOn(string? s) =>
                !string.IsNullOrWhiteSpace(s) &&
                s.Trim().Equals("On", StringComparison.OrdinalIgnoreCase);

            string NormalizeOnOff(string? v)
            {
                if (string.IsNullOrWhiteSpace(v)) return "Unknown";
                var t = v.Trim();
                return t.Equals("On", StringComparison.OrdinalIgnoreCase) ? "On"
                     : t.Equals("Off", StringComparison.OrdinalIgnoreCase) ? "Off"
                     : t.Equals("Eval", StringComparison.OrdinalIgnoreCase) ? "Eval"
                     : t;
            }

            var policy = _compliancePolicy;

            AddBool("Real-Time Protection",        policy.RequireRealTimeProtection,   DefenderStatus.RealTimeProtection,      IsOn(DefenderStatus.RealTimeProtection),      "Core malware monitoring.");
            AddBool("Tamper Protection",           policy.RequireTamperProtection,     DefenderStatus.TamperProtectionDisplay, DefenderStatus.IsTamperProtected == true,    "Protects Defender settings.");
            AddBool("Firewall Enabled",            policy.RequireFirewall,             FirewallProfileStatusesDisplay.Any(p => p.Enabled) ? "On" : "Off", FirewallProfileStatusesDisplay.Any(p => p.Enabled), "At least one enabled profile.");
            AddBool("Device Control Enabled",      policy.RequireDeviceControlEnabled, DefenderStatus.DeviceControlState,      !string.IsNullOrWhiteSpace(DefenderStatus.DeviceControlState) &&
                                                                                                                             !DefenderStatus.DeviceControlState.Contains("Disabled", StringComparison.OrdinalIgnoreCase),
                                                                                                                             "Device Control active.");
            AddBool("Cloud Protection",            policy.RequireCloudProtection,      DefenderStatus.CloudProtection,         IsOn(DefenderStatus.CloudProtection),         "MAPS cloud protection.");
            AddBool("Sample Submission",           policy.RequireSampleSubmission,     DefenderStatus.SampleSubmission,        IsOn(DefenderStatus.SampleSubmission),        "Automatic sample submission.");
            AddBool("IOAV Protection",             policy.RequireIoavProtection,       DefenderStatus.IoavProtection,          IsOn(DefenderStatus.IoavProtection),          "Inbound / file download scanning.");
            AddBool("On-Access Protection",        policy.RequireOnAccessProtection,   DefenderStatus.OnAccessProtection,      IsOn(DefenderStatus.OnAccessProtection),      "On-access file scanning.");
            AddBool("Smart App Control",           policy.RequireSmartAppControlOn,    DefenderStatus.SmartAppControl,         DefenderStatus.SmartAppControl.Equals("On", StringComparison.OrdinalIgnoreCase)
                                                                                                                             || DefenderStatus.SmartAppControl.Equals("Eval", StringComparison.OrdinalIgnoreCase),
                                                                                                                             "Smart App Control enforced (Eval accepted).");
            AddBool("Antivirus Enabled",           policy.RequireAntivirusEnabled,     DefenderStatus.RealTimeProtection,      IsOn(DefenderStatus.RealTimeProtection),      "Using Real-Time Protection as proxy.");

            int? ParseHours(string? v)
            {
                if (string.IsNullOrWhiteSpace(v)) return null;
                var digits = new string(v.Where(char.IsDigit).ToArray());
                if (int.TryParse(digits, out var h)) return h;
                return null;
            }

            if (policy.RequireSignaturesUpToDate)
            {
                AddAge("AV Signatures Age (hrs)",  policy.MaxAntivirusSignatureAgeHours,   ParseHours(DefenderStatus.AntivirusSignatureAge),   "Antivirus signature freshness.");
                AddAge("ASW Signatures Age (hrs)", policy.MaxAntispywareSignatureAgeHours, ParseHours(DefenderStatus.AntispywareSignatureAge), "Antispyware signature freshness.");
            }
            else
            {
                AddAge("AV Signatures Age (hrs)", 0, ParseHours(DefenderStatus.AntivirusSignatureAge),   "Not configured.");
                AddAge("ASW Signatures Age (hrs)",0, ParseHours(DefenderStatus.AntispywareSignatureAge), "Not configured.");
            }

            AddAge("Full Scan Age (days)",  policy.MaxFullScanAgeDays,  DefenderStatus.FullScanAgeDays,  "Scan timestamp from WMI.");
            AddAge("Quick Scan Age (days)", policy.MaxQuickScanAgeDays, DefenderStatus.QuickScanAgeDays, "Scan timestamp from WMI.");

            if (policy.DeviceControlGroupIds is { Count: > 0 })
            {
                var missing = policy.DeviceControlGroupIds.Where(id =>
                    DeviceControlPolicyGroups == null ||
                    !DeviceControlPolicyGroups.Any(g => string.Equals(g.Id, id, StringComparison.OrdinalIgnoreCase))).ToList();
                ComplianceItems.Add(new ComplianceItem
                {
                    Name = "Device Control Group IDs",
                    RequiredDisplay = string.Join(", ", policy.DeviceControlGroupIds),
                    CurrentDisplay = DeviceControlPolicyGroups == null ? "(none)" :
                        string.Join(", ", DeviceControlPolicyGroups.Select(g => g.Id)),
                    Compliant = missing.Count == 0,
                    CompliantDisplay = missing.Count == 0 ? "Yes" : "No",
                    Notes = missing.Count == 0 ? "All present" : "Missing: " + string.Join(", ", missing)
                });
            }
            else
            {
                ComplianceItems.Add(new ComplianceItem
                {
                    Name = "Device Control Group IDs",
                    RequiredDisplay = "Not configured",
                    CurrentDisplay = DeviceControlPolicyGroups == null ? "(none)" :
                        string.Join(", ", DeviceControlPolicyGroups.Select(g => g.Id)),
                    Compliant = true,
                    CompliantDisplay = "N/A",
                    Notes = "No required group IDs."
                });
            }

            if (policy.DeviceControlRuleIds is { Count: > 0 })
            {
                var missing = policy.DeviceControlRuleIds.Where(id =>
                    DeviceControlPolicyRules == null ||
                    !DeviceControlPolicyRules.Any(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase))).ToList();
                ComplianceItems.Add(new ComplianceItem
                {
                    Name = "Device Control Rule IDs",
                    RequiredDisplay = string.Join(", ", policy.DeviceControlRuleIds),
                    CurrentDisplay = DeviceControlPolicyRules == null ? "(none)" :
                        string.Join(", ", DeviceControlPolicyRules.Select(r => r.Id)),
                    Compliant = missing.Count == 0,
                    CompliantDisplay = missing.Count == 0 ? "Yes" : "No",
                    Notes = missing.Count == 0 ? "All present" : "Missing: " + string.Join(", ", missing)
                });
            }
            else
            {
                ComplianceItems.Add(new ComplianceItem
                {
                    Name = "Device Control Rule IDs",
                    RequiredDisplay = "Not configured",
                    CurrentDisplay = DeviceControlPolicyRules == null ? "(none)" :
                        string.Join(", ", DeviceControlPolicyRules.Select(r => r.Id)),
                    Compliant = true,
                    CompliantDisplay = "N/A",
                    Notes = "No required rule IDs."
                });
            }

            var evaluable = ComplianceItems.Where(ci => !string.Equals(ci.RequiredDisplay, "Not configured", StringComparison.OrdinalIgnoreCase)).ToList();
            var passed = evaluable.Count(ci => ci.Compliant);
            CompliancePercentage = evaluable.Count == 0 ? 100 : (double)passed / evaluable.Count * 100.0;
            OnPropertyChanged(nameof(ComplianceSummaryDisplay));

            void AddBool(string name, bool requiredFlag, string rawValue, bool isOn, string notes)
            {
                ComplianceItems.Add(new ComplianceItem
                {
                    Name = name,
                    RequiredDisplay = requiredFlag ? "Required" : "Not configured",
                    CurrentDisplay = NormalizeOnOff(rawValue),
                    Compliant = requiredFlag ? isOn : true,
                    CompliantDisplay = requiredFlag ? (isOn ? "Yes" : "No") : "N/A",
                    Notes = notes
                });
            }

            void AddAge(string name, int maxAllowed, int? current, string notes)
            {
                bool required = maxAllowed > 0;
                bool ok = !required || (current.HasValue && current.Value <= maxAllowed);
                ComplianceItems.Add(new ComplianceItem
                {
                    Name = name,
                    RequiredDisplay = required ? ("<=" + maxAllowed) : "Not configured",
                    CurrentDisplay = current.HasValue ? current.Value.ToString() : "Unknown",
                    Compliant = ok,
                    CompliantDisplay = required ? (ok ? "Yes" : "No") : "N/A",
                    Notes = notes
                });
            }
        }

        // --- Compliance item model (add at end of file, inside namespace but outside MainViewModel) ---
        public sealed class ComplianceItem
        {
            public string Name { get; set; } = "";
            public string RequiredDisplay { get; set; } = "";
            public string CurrentDisplay { get; set; } = "";
            public bool Compliant { get; set; }
            public string CompliantDisplay { get; set; } = "";
            public string Notes { get; set; } = "";
        }
    }
}
