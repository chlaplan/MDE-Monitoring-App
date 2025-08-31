using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace MDE_Monitoring_App.Models
{
    // MDE Defender status model with change notification for UI binding
    public class DefenderStatus : INotifyPropertyChanged
    {
        private string _amProductVersion = string.Empty;
        private string _amEngineVersion = string.Empty;
        private string _amRunningMode = string.Empty;
        private string _realTimeProtection = string.Empty;
        private string _antivirusSignatureAge = string.Empty;
        private string _antispywareSignatureAge = string.Empty;
        private string _deviceControlDefaultEnforcement = string.Empty;
        private string _deviceControlState = string.Empty;

        public string AMProductVersion { get => _amProductVersion; set => Set(ref _amProductVersion, value); }
        public string AMEngineVersion { get => _amEngineVersion; set => Set(ref _amEngineVersion, value); }
        public string AMRunningMode { get => _amRunningMode; set => Set(ref _amRunningMode, value); }
        public string RealTimeProtection { get => _realTimeProtection; set => Set(ref _realTimeProtection, value); }
        public string AntivirusSignatureAge { get => _antivirusSignatureAge; set => Set(ref _antivirusSignatureAge, value); }
        public string AntispywareSignatureAge { get => _antispywareSignatureAge; set => Set(ref _antispywareSignatureAge, value); }
        public string DeviceControlDefaultEnforcement { get => _deviceControlDefaultEnforcement; set => Set(ref _deviceControlDefaultEnforcement, value); }
        public string DeviceControlState { get => _deviceControlState; set => Set(ref _deviceControlState, value); }

        public event PropertyChangedEventHandler PropertyChanged;
        private void Set<T>(ref T field, T value, [CallerMemberName] string? prop = null)
        {
            if (!Equals(field, value))
            {
                field = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
            }
        }
    }
}


