using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;

namespace MDE_Monitoring_App
{
    public class MainViewModel : INotifyPropertyChanged
    {
        public ObservableCollection<LogEntry> Logs { get; set; }
        public ICollectionView LogsView { get; set; }

        private string _logFilter = "All";
        public string LogFilter
        {
            get => _logFilter;
            set
            {
                if (_logFilter != value)
                {
                    _logFilter = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(LogFilter)));
                    LogsView.Refresh();
                }
            }
        }

        public DefenderStatus DefenderStatus { get; set; } = new DefenderStatus();

        private DateTime _lastRefreshed;
        public DateTime LastRefreshed
        {
            get => _lastRefreshed;
            set { _lastRefreshed = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(LastRefreshed))); }
        }

        public MainViewModel()
        {
            Logs = new ObservableCollection<LogEntry>();
            LogsView = CollectionViewSource.GetDefaultView(Logs);
            LogsView.Filter = LogFilterPredicate;

            RefreshData();
        }

        private bool LogFilterPredicate(object obj)
        {
            if (obj is LogEntry log)
            {
                if (LogFilter == "All") return true;
                return log.Level.Equals(LogFilter, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        public void RefreshData()
        {
            try
            {
                // Live Defender status
                var liveStatus = DefenderService.GetLiveStatus();
                if (liveStatus != null)
                {
                    DefenderStatus.AMProductVersion = liveStatus.AMProductVersion;
                    DefenderStatus.AMEngineVersion = liveStatus.AMEngineVersion;
                    DefenderStatus.AMRunningMode = liveStatus.AMRunningMode;
                    DefenderStatus.RealTimeProtection = liveStatus.RealTimeProtection;
                    DefenderStatus.AntivirusSignatureAge = liveStatus.AntivirusSignatureAge;
                    DefenderStatus.AntispywareSignatureAge = liveStatus.AntispywareSignatureAge;
                    DefenderStatus.DeviceControlDefaultEnforcement = liveStatus.DeviceControlDefaultEnforcement;
                    DefenderStatus.DeviceControlState = liveStatus.DeviceControlState;
                }

                // Get real MDE events
                Logs.Clear();
                var recentEvents = DefenderService.GetRecentMDEEvents(50);
                foreach (var ev in recentEvents)
                    Logs.Add(ev);

                Logs.Insert(0, new LogEntry
                {
                    Time = DateTime.Now,
                    Level = "Info",
                    Message = "MDE status refreshed."
                });

                LastRefreshed = DateTime.Now;
                LogsView.Refresh();
            }
            catch (Exception ex)
            {
                Logs.Insert(0, new LogEntry
                {
                    Time = DateTime.Now,
                    Level = "Error",
                    Message = $"Failed to refresh: {ex.Message}"
                });
                LogsView.Refresh();
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
    }

    public class LogEntry
    {
        public DateTime Time { get; set; }
        public string Level { get; set; }
        public string Message { get; set; }
    }

    public class DefenderStatus : INotifyPropertyChanged
    {
        public string AMProductVersion { get; set; }
        public string AMEngineVersion { get; set; }
        public string AMRunningMode { get; set; }
        public string RealTimeProtection { get; set; }
        public string AntivirusSignatureAge { get; set; }
        public string AntispywareSignatureAge { get; set; }
        public string DeviceControlDefaultEnforcement { get; set; }
        public string DeviceControlState { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;
    }
}
