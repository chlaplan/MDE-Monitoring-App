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

namespace MDE_Monitoring_App
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private readonly DefenderStatusService _defenderStatusService = new();
        private readonly LogCollector _logCollector = new();
        private readonly FirewallLogService _firewallLogService = new();
        private readonly DefenderPolicyService _policyService = new(); // NEW

        public ObservableCollection<LogEntry> Logs { get; } = new();
        private ObservableCollection<DeviceControlEvent> _deviceControlEvents = new();
        public ObservableCollection<DeviceControlEvent> DeviceControlEvents
        {
            get => _deviceControlEvents;
            private set { if (value != _deviceControlEvents) { _deviceControlEvents = value; OnPropertyChanged(); } }
        }

        public ObservableCollection<FirewallLogEntry> FirewallEvents { get; } = new();
        public ObservableCollection<PolicySetting> DefenderPolicies { get; } = new(); // NEW

        public ICollectionView LogsView { get; }
        public ICollectionView FirewallView { get; }
        public ICollectionView PolicyView { get; }  // optional view (for later filtering)
        public DefenderStatus DefenderStatus { get; } = new();
        public MDE_Monitoring_App.Models.SystemInfo CurrentSystem { get; } = new();

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

        // Single global firewall filter text
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

        public MainViewModel()
        {
            LogsView = CollectionViewSource.GetDefaultView(Logs);
            LogsView.Filter = LogFilterPredicate;

            FirewallView = CollectionViewSource.GetDefaultView(FirewallEvents);
            FirewallView.Filter = FirewallFilter;

            PolicyView = CollectionViewSource.GetDefaultView(DefenderPolicies);

            _ = RefreshDataAsync();
        }

        private bool LogFilterPredicate(object obj)
        {
            if (obj is not LogEntry log) return false;
            if (LogFilter == "All") return true;
            return log.Level.Equals(LogFilter, StringComparison.OrdinalIgnoreCase);
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

        public async Task RefreshDataAsync()
        {
            try
            {
                var dcTask = Task.Run(() => DeviceControlService.LoadLatestDeviceControlEvents());
                var logsTask = Task.Run(() => _logCollector.GetDefenderLogs(50));
                var statusTask = Task.Run(() => _defenderStatusService.GetStatus());
                var firewallTask = Task.Run(() => _firewallLogService.LoadRecentDrops(200));
                var policyTask = Task.Run(() => _policyService.LoadPolicies()); // NEW

                var dcEvents = await dcTask.ConfigureAwait(false);
                var newLogs = await logsTask.ConfigureAwait(false);
                var newStatus = await statusTask.ConfigureAwait(false);
                var fwEvents = await firewallTask.ConfigureAwait(false);
                var policies = await policyTask.ConfigureAwait(false); // NEW

                App.Current.Dispatcher.Invoke(() =>
                {
                    DeviceControlEvents = new ObservableCollection<DeviceControlEvent>(dcEvents);

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

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? prop = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
}
