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
        private bool? _isTamperProtected = null;
        private string _cloudProtection = string.Empty;
        private string _sampleSubmission = string.Empty;
        private string _ioavProtection = string.Empty;
        private string _onAccessProtection = string.Empty;
        private string _smartAppControl = string.Empty;
        private int? _quickScanAgeDays;
        private int? _fullScanAgeDays;

        public string AMProductVersion { get => _amProductVersion; set => Set(ref _amProductVersion, value); }
        public string AMEngineVersion { get => _amEngineVersion; set => Set(ref _amEngineVersion, value); }
        public string AMRunningMode { get => _amRunningMode; set => Set(ref _amRunningMode, value); }
        public string RealTimeProtection { get => _realTimeProtection; set => Set(ref _realTimeProtection, value); }
        public string AntivirusSignatureAge { get => _antivirusSignatureAge; set => Set(ref _antivirusSignatureAge, value); }
        public string AntispywareSignatureAge { get => _antispywareSignatureAge; set => Set(ref _antispywareSignatureAge, value); }
        public string DeviceControlDefaultEnforcement { get => _deviceControlDefaultEnforcement; set => Set(ref _deviceControlDefaultEnforcement, value); }
        public string DeviceControlState { get => _deviceControlState; set => Set(ref _deviceControlState, value); }
        public bool? IsTamperProtected { get => _isTamperProtected; set => Set(ref _isTamperProtected, value); }
        public string CloudProtection { get => _cloudProtection; set => Set(ref _cloudProtection, value); }
        public string SampleSubmission { get => _sampleSubmission; set => Set(ref _sampleSubmission, value); }
        public string IoavProtection { get => _ioavProtection; set => Set(ref _ioavProtection, value); }
        public string OnAccessProtection { get => _onAccessProtection; set => Set(ref _onAccessProtection, value); }
        public string SmartAppControl { get => _smartAppControl; set => Set(ref _smartAppControl, value); }
        public int? QuickScanAgeDays { get => _quickScanAgeDays; set => Set(ref _quickScanAgeDays, value); }
        public int? FullScanAgeDays { get => _fullScanAgeDays; set => Set(ref _fullScanAgeDays, value); }

        public string TamperProtectionDisplay =>
            IsTamperProtected switch
            {
                true => "Tamper Protection: Enabled",
                false => "Tamper Protection: Disabled",
                _ => "Tamper Protection: Unknown"
            };

        public string DeviceControlDefaultEnforcementDisplay =>
            string.IsNullOrWhiteSpace(DeviceControlDefaultEnforcement)
                ? "Disabled (Device control disabled)"
                : DeviceControlDefaultEnforcement;

        // Optional helper: normalize to On/Off
        public static string BoolDisplay(bool? b) => b == true ? "On" : b == false ? "Off" : "Unknown";

        public event PropertyChangedEventHandler? PropertyChanged;
        private void Set<T>(ref T field, T value, [CallerMemberName] string? prop = null)
        {
            if (Equals(field, value)) return;
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
            if (prop == nameof(DeviceControlDefaultEnforcement))
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DeviceControlDefaultEnforcementDisplay)));
            if (prop == nameof(IsTamperProtected))
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(TamperProtectionDisplay)));
        }
    }
}


