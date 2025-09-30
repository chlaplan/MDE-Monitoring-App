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

        public ObservableCollection<LogEntry> Logs { get; } = new();
        private ObservableCollection<DeviceControlEvent> _deviceControlEvents = new();
        public ObservableCollection<DeviceControlEvent> DeviceControlEvents
        {
            get => _deviceControlEvents;
            private set { if (value != _deviceControlEvents) { _deviceControlEvents = value; OnPropertyChanged(); } }
        }

        public ObservableCollection<FirewallLogEntry> FirewallEvents { get; } = new();
        public ObservableCollection<PolicySetting> DefenderPolicies { get; } = new();
        public ObservableCollection<AppControlEvent> AppControlEvents { get; } = new();

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

        // Backing fields & public (safe) writable properties
        private string _platformStatusText = "Unknown";
        private string _engineStatusText = "Unknown";

        public string PlatformStatusText
        {
            get => _platformStatusText;
            set
            {
                // Ignore external TwoWay writes; recompute to maintain consistency
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

        // Computed health booleans (kept for triggers / other logic)
        public bool PlatformUpToDate => IsUpToDate(DefenderStatus.AMProductVersion, LatestVersions?.PlatformVersion);
        public bool EngineUpToDate => IsUpToDate(DefenderStatus.AMEngineVersion, LatestVersions?.EngineVersion);

        private void RaiseVersionProps()
        {
            // Recompute text first
            var newPlat = BuildStatusText(DefenderStatus.AMProductVersion, LatestVersions?.PlatformVersion, PlatformUpToDate);
            var newEng  = BuildStatusText(DefenderStatus.AMEngineVersion,   LatestVersions?.EngineVersion,   EngineUpToDate);

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
            if (string.IsNullOrWhiteSpace(local) || string.IsNullOrWhiteSpace(latest)) return true; // treat unknown latest as neutral (won't show red)
            if (!Version.TryParse(Normalize(local), out var lv)) return true;
            if (!Version.TryParse(Normalize(latest), out var rv)) return true;
            return lv >= rv;
        }

        private static string BuildStatusText(string? local, string? latest, bool upToDate)
        {
            if (string.IsNullOrWhiteSpace(local)) return "Unknown";
            if (latest == null || latest.Length == 0)
                return local + " (Unavailable)"; // failed or not parsed
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

            // Time window filter
            var cutoff = DateTime.Now.AddHours(-LogTimeRangeHours);
            if (entry.Time < cutoff) return false;

            // Level filter
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
                    // Recompute text if state affects wording
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
            set { /* ignore incoming writes to keep read-only semantics */ }
        }

        public string IntuneLastSyncUtcDisplay
        {
            get => _intuneLastSyncUtc.HasValue ? _intuneLastSyncUtc.Value.ToString("u") : "Unknown";
            set { /* ignore */ }
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
            }
        }

        public string CodeIntegrityPolicyDisplay => "Code Integrity Policy: " + DeviceGuardStatus.CodeIntegrityPolicyDisplay;
        public string VbsStatusDisplay => "VBS Status: " + DeviceGuardStatus.VbsStatusDisplay;
        public string SecurityServicesConfiguredDisplay => "Configured Services: " + DeviceGuardStatus.SecurityServicesConfiguredDisplay;
        public string SecurityServicesRunningDisplay => "Running Services: " + DeviceGuardStatus.SecurityServicesRunningDisplay;

        private async Task<DeviceGuardStatus> LoadDeviceGuardStatusAsync()
        {
            // Slightly artificial delay to simulate real-world async data loading
            await Task.Delay(500).ConfigureAwait(false);
            return new DeviceGuardStatus
            {
                // Only set writable properties, not read-only display properties
                CodeIntegrityPolicyEnforcementStatus = 1,
                VirtualizationBasedSecurityStatus = 1,
                SecurityServicesConfigured = new uint[] { 1 },
                SecurityServicesRunning = new uint[] { 1 },
            };
        }

        public async Task RefreshDataAsync()
        {
            try
            {
                // Replace this line:
                // var dcTask = Task.Run(DeviceControlService.LoadLatestDeviceControlEvents);

                // With this line:
                var dcTask = Task.Run(() => DeviceControlService.LoadLatestDeviceControlEvents());
                var logsTask = Task.Run(() => _logCollector.GetDefenderLogs());
                var statusTask = Task.Run(_defenderStatusService.GetStatus);
                var firewallTask = Task.Run(() => _firewallLogService.LoadRecentDrops(200));
                var policyTask = Task.Run(_policyService.LoadPolicies);
                var latestTask = _latestVersionService.GetLatestAsync();
                var intuneSyncTask = Task.Run(_intuneSyncService.GetLastSync);
                var appControlStatusTask = Task.Run(_appControlStatusService.GetStatus);
                var appControlLogsTask = Task.Run(() => _appControlLogService.GetRecent(150));
                //var deviceGuardStatusTask = Task.Run(LoadDeviceGuardStatusAsync);
                var deviceGuardTask = Task.Run(_deviceGuardStatusService.GetStatus);

                var dcEvents = await dcTask.ConfigureAwait(false);
                var newLogs = await logsTask.ConfigureAwait(false);
                var newStatus = await statusTask.ConfigureAwait(false);
                var fwEvents = await firewallTask.ConfigureAwait(false);
                var policies = await policyTask.ConfigureAwait(false);
                var latest = await latestTask.ConfigureAwait(false);
                var intuneLastSync = await intuneSyncTask.ConfigureAwait(false);
                var appControlStatus = await appControlStatusTask.ConfigureAwait(false);
                var appControlLogs = await appControlLogsTask.ConfigureAwait(false);
                //var deviceGuardStatus = await deviceGuardStatusTask.ConfigureAwait(false);
                var deviceGuardStatus = await deviceGuardTask.ConfigureAwait(false);

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

                    CurrentSystem.CurrentUser = Environment.UserName;
                    CurrentSystem.MachineName = Environment.MachineName;
                    CurrentSystem.IPAddress = GetLocalIPAddress();
                    CurrentSystem.JoinType = GetAADJoinType();

                    // With the following, using the correct variable names:
                    LatestVersions = latest.versions;
                    LatestFetchState = latest.state;
                    LatestFetchError = latest.error;
                    IntuneLastSyncUtc = intuneLastSync;

                    // In your RefreshDataAsync method, replace this line:
                    AppControlStatus = appControlStatus;

                    AppControlEvents.Clear();
                    foreach (var ev in appControlLogs) AppControlEvents.Add(ev);

                    DeviceGuardStatus = deviceGuardStatus;

                    LastRefreshed = DateTime.Now;
                    LogsView.Refresh();
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
                });
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
        // Add this property to your MainViewModel class
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
                FirewallLoggingStatusMessage = string.Empty; // All good, hide message
                return;
            }

            var parts = new List<string>();
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
        // Heavy work off UI thread
        var bytes = await Task.Run(() => exporter.BuildReport(this), ct).ConfigureAwait(false);
        await File.WriteAllBytesAsync(filePath, bytes, ct).ConfigureAwait(false);
        return true;
    }
    catch
    {
        return false;
    }
}
    }
}
