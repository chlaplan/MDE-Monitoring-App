using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;

namespace MDE_Monitoring_App;

public sealed class ComplianceManagerViewModel : INotifyPropertyChanged
{
    private readonly MainViewModel? _root;

    public ComplianceManagerViewModel(MainViewModel? root)
    {
        _root = root;
        NewPolicyCommand = new RelayCommand(_ => NewPolicy());
        SavePolicyCommand = new RelayCommand(_ => SavePolicy(), _ => CanSave());
        LoadPolicyCommand = new RelayCommand(_ => LoadPolicy());
        CloseWindowCommand = new RelayCommand(o =>
        {
            if (o is Window w) w.Close();
            else Application.Current.Windows.OfType<Window>()
                .FirstOrDefault(x => x.DataContext == this)?.Close();
        });

        LoadPolicy(); // auto-load if file exists
        if (string.IsNullOrWhiteSpace(EditingName))
        {
            EditingName = "Baseline";
            EditingDescription = "Baseline defender compliance.";
        }
    }

    // Display-only
    public string CurrentPolicyName { get => _currentPolicyName; private set => Set(ref _currentPolicyName, value); }
    private string _currentPolicyName = "(unsaved)";

    // Editable fields
    public string EditingName { get => _editingName; set { if (Set(ref _editingName, value)) RaiseCanExecutes(); } }
    private string _editingName = string.Empty;

    public string EditingDescription { get => _editingDescription; set => Set(ref _editingDescription, value); }
    private string _editingDescription = string.Empty;

    public bool RequireRealTimeProtection { get => _requireRealTimeProtection; set => Set(ref _requireRealTimeProtection, value); }
    private bool _requireRealTimeProtection;

    public bool RequireTamperProtection { get => _requireTamperProtection; set => Set(ref _requireTamperProtection, value); }
    private bool _requireTamperProtection;

    public bool RequireCloudProtection { get => _requireCloudProtection; set => Set(ref _requireCloudProtection, value); }
    private bool _requireCloudProtection;

    public bool RequireSampleSubmission { get => _requireSampleSubmission; set => Set(ref _requireSampleSubmission, value); }
    private bool _requireSampleSubmission;

    public bool RequireFirewall { get => _requireFirewall; set => Set(ref _requireFirewall, value); }
    private bool _requireFirewall;

    public bool RequireIoavProtection { get => _requireIoavProtection; set => Set(ref _requireIoavProtection, value); }
    private bool _requireIoavProtection;

    public bool RequireOnAccessProtection { get => _requireOnAccessProtection; set => Set(ref _requireOnAccessProtection, value); }
    private bool _requireOnAccessProtection;

    public bool RequireAntivirusEnabled { get => _requireAntivirusEnabled; set => Set(ref _requireAntivirusEnabled, value); }
    private bool _requireAntivirusEnabled;

    public bool RequireDeviceControlEnabled { get => _requireDeviceControlEnabled; set => Set(ref _requireDeviceControlEnabled, value); }
    private bool _requireDeviceControlEnabled;

    public bool RequireSmartAppControlOn { get => _requireSmartAppControlOn; set => Set(ref _requireSmartAppControlOn, value); }
    private bool _requireSmartAppControlOn;

    public bool RequireSignaturesUpToDate { get => _requireSignaturesUpToDate; set => Set(ref _requireSignaturesUpToDate, value); }
    private bool _requireSignaturesUpToDate;

    public int MaxFullScanAgeDays { get => _maxFullScanAgeDays; set => Set(ref _maxFullScanAgeDays, Math.Clamp(value, 0, 365)); }
    private int _maxFullScanAgeDays = 30;

    public int MaxQuickScanAgeDays { get => _maxQuickScanAgeDays; set => Set(ref _maxQuickScanAgeDays, Math.Clamp(value, 0, 365)); }
    private int _maxQuickScanAgeDays = 7;

    public int MaxAntivirusSignatureAgeHours { get => _maxAntivirusSignatureAgeHours; set => Set(ref _maxAntivirusSignatureAgeHours, Math.Clamp(value, 0, 168)); }
    private int _maxAntivirusSignatureAgeHours = 24;

    public int MaxAntispywareSignatureAgeHours { get => _maxAntispywareSignatureAgeHours; set => Set(ref _maxAntispywareSignatureAgeHours, Math.Clamp(value, 0, 168)); }
    private int _maxAntispywareSignatureAgeHours = 24;

    // Device Control IDs (editable text)
    public string EditingDeviceControlGroupIds { get => _editingDeviceControlGroupIds; set => Set(ref _editingDeviceControlGroupIds, value); }
    private string _editingDeviceControlGroupIds = string.Empty;

    public string EditingDeviceControlRuleIds { get => _editingDeviceControlRuleIds; set => Set(ref _editingDeviceControlRuleIds, value); }
    private string _editingDeviceControlRuleIds = string.Empty;

    public string StatusMessage { get => _statusMessage; set => Set(ref _statusMessage, value); }
    private string _statusMessage = "Ready";

    // Commands
    public ICommand NewPolicyCommand { get; }
    public ICommand SavePolicyCommand { get; }
    public ICommand LoadPolicyCommand { get; }
    public ICommand CloseWindowCommand { get; }

    private void NewPolicy()
    {
        EditingName = string.Empty;
        EditingDescription = string.Empty;
        RequireRealTimeProtection = RequireTamperProtection = RequireCloudProtection =
            RequireSampleSubmission = RequireFirewall = RequireIoavProtection =
            RequireOnAccessProtection = RequireAntivirusEnabled = RequireDeviceControlEnabled =
            RequireSmartAppControlOn = RequireSignaturesUpToDate = false;
        MaxFullScanAgeDays = 30;
        MaxQuickScanAgeDays = 7;
        MaxAntivirusSignatureAgeHours = 24;
        MaxAntispywareSignatureAgeHours = 24;
        EditingDeviceControlGroupIds = string.Empty;
        EditingDeviceControlRuleIds = string.Empty;
        CurrentPolicyName = "(unsaved)";
        StatusMessage = "New policy draft.";
    }

    private bool CanSave() => !string.IsNullOrWhiteSpace(EditingName);

    private void SavePolicy()
    {
        if (!CanSave())
        {
            StatusMessage = "Name required.";
            return;
        }
        try
        {
            var path = System.IO.Path.Combine(AppContext.BaseDirectory, "CompliancePolicy.config.json");
            var policy = BuildPolicyObject();
            var json = JsonSerializer.Serialize(policy, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(path, json);
            CurrentPolicyName = policy.Name;
            StatusMessage = "Policy saved.";
        }
        catch (Exception ex)
        {
            StatusMessage = "Save failed: " + ex.Message;
        }
        RaiseCanExecutes();
    }

    private void LoadPolicy()
    {
        try
        {
            var path = System.IO.Path.Combine(AppContext.BaseDirectory, "CompliancePolicy.config.json");
            if (!System.IO.File.Exists(path))
            {
                StatusMessage = "No saved policy found.";
                return;
            }
            var json = System.IO.File.ReadAllText(path);
            var policy = JsonSerializer.Deserialize<CompliancePolicy>(json);
            if (policy == null)
            {
                StatusMessage = "Load failed: null policy.";
                return;
            }
            ApplyPolicyToEditing(policy);
            CurrentPolicyName = policy.Name;
            StatusMessage = "Policy loaded.";
        }
        catch (Exception ex)
        {
            StatusMessage = "Load failed: " + ex.Message;
        }
        RaiseCanExecutes();
    }

    private CompliancePolicy BuildPolicyObject() => new()
    {
        Name = EditingName.Trim(),
        Description = EditingDescription?.Trim() ?? string.Empty,
        RequireRealTimeProtection = RequireRealTimeProtection,
        RequireTamperProtection = RequireTamperProtection,
        RequireCloudProtection = RequireCloudProtection,
        RequireSampleSubmission = RequireSampleSubmission,
        RequireFirewall = RequireFirewall,
        RequireIoavProtection = RequireIoavProtection,
        RequireOnAccessProtection = RequireOnAccessProtection,
        RequireAntivirusEnabled = RequireAntivirusEnabled,
        RequireDeviceControlEnabled = RequireDeviceControlEnabled,
        RequireSmartAppControlOn = RequireSmartAppControlOn,
        RequireSignaturesUpToDate = RequireSignaturesUpToDate,
        MaxFullScanAgeDays = MaxFullScanAgeDays,
        MaxQuickScanAgeDays = MaxQuickScanAgeDays,
        MaxAntivirusSignatureAgeHours = MaxAntivirusSignatureAgeHours,
        MaxAntispywareSignatureAgeHours = MaxAntispywareSignatureAgeHours,
        DeviceControlGroupIds = ParseIds(EditingDeviceControlGroupIds),
        DeviceControlRuleIds = ParseIds(EditingDeviceControlRuleIds)
    };

    private void ApplyPolicyToEditing(CompliancePolicy p)
    {
        EditingName = p.Name;
        EditingDescription = p.Description;
        RequireRealTimeProtection = p.RequireRealTimeProtection;
        RequireTamperProtection = p.RequireTamperProtection;
        RequireCloudProtection = p.RequireCloudProtection;
        RequireSampleSubmission = p.RequireSampleSubmission;
        RequireFirewall = p.RequireFirewall;
        RequireIoavProtection = p.RequireIoavProtection;
        RequireOnAccessProtection = p.RequireOnAccessProtection;
        RequireAntivirusEnabled = p.RequireAntivirusEnabled;
        RequireDeviceControlEnabled = p.RequireDeviceControlEnabled;
        RequireSmartAppControlOn = p.RequireSmartAppControlOn;
        RequireSignaturesUpToDate = p.RequireSignaturesUpToDate;
        MaxFullScanAgeDays = p.MaxFullScanAgeDays;
        MaxQuickScanAgeDays = p.MaxQuickScanAgeDays;
        MaxAntivirusSignatureAgeHours = p.MaxAntivirusSignatureAgeHours;
        MaxAntispywareSignatureAgeHours = p.MaxAntispywareSignatureAgeHours;
        EditingDeviceControlGroupIds = string.Join(Environment.NewLine, p.DeviceControlGroupIds ?? new List<string>());
        EditingDeviceControlRuleIds = string.Join(Environment.NewLine, p.DeviceControlRuleIds ?? new List<string>());
    }

    private static List<string> ParseIds(string text) =>
        (text ?? string.Empty)
            .Split(new[] { '\r', '\n', ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private void RaiseCanExecutes() =>
        (SavePolicyCommand as RelayCommand)?.RaiseCanExecuteChanged();

    public event PropertyChangedEventHandler? PropertyChanged;
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        return true;
    }

    private sealed class RelayCommand : ICommand
    {
        private readonly Action<object?> _exec;
        private readonly Predicate<object?>? _can;
        public RelayCommand(Action<object?> exec, Predicate<object?>? can = null)
        {
            _exec = exec;
            _can = can;
        }
        public bool CanExecute(object? parameter) => _can?.Invoke(parameter) ?? true;
        public void Execute(object? parameter) => _exec(parameter);
        public event EventHandler? CanExecuteChanged;
        public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}

public sealed class CompliancePolicy : INotifyPropertyChanged
{
    private string _name = string.Empty;
    public string Name { get => _name; set { if (_name != value) { _name = value; OnPropertyChanged(); } } }

    private string _description = string.Empty;
    public string Description { get => _description; set { if (_description != value) { _description = value; OnPropertyChanged(); } } }

    private bool _requireRealTimeProtection;
    public bool RequireRealTimeProtection { get => _requireRealTimeProtection; set { if (_requireRealTimeProtection != value) { _requireRealTimeProtection = value; OnPropertyChanged(); } } }

    private bool _requireTamperProtection;
    public bool RequireTamperProtection { get => _requireTamperProtection; set { if (_requireTamperProtection != value) { _requireTamperProtection = value; OnPropertyChanged(); } } }

    private bool _requireCloudProtection;
    public bool RequireCloudProtection { get => _requireCloudProtection; set { if (_requireCloudProtection != value) { _requireCloudProtection = value; OnPropertyChanged(); } } }

    private bool _requireSampleSubmission;
    public bool RequireSampleSubmission { get => _requireSampleSubmission; set { if (_requireSampleSubmission != value) { _requireSampleSubmission = value; OnPropertyChanged(); } } }

    private bool _requireFirewall;
    public bool RequireFirewall { get => _requireFirewall; set { if (_requireFirewall != value) { _requireFirewall = value; OnPropertyChanged(); } } }

    private bool _requireIoavProtection;
    public bool RequireIoavProtection { get => _requireIoavProtection; set { if (_requireIoavProtection != value) { _requireIoavProtection = value; OnPropertyChanged(); } } }

    private bool _requireOnAccessProtection;
    public bool RequireOnAccessProtection { get => _requireOnAccessProtection; set { if (_requireOnAccessProtection != value) { _requireOnAccessProtection = value; OnPropertyChanged(); } } }

    private bool _requireAntivirusEnabled;
    public bool RequireAntivirusEnabled { get => _requireAntivirusEnabled; set { if (_requireAntivirusEnabled != value) { _requireAntivirusEnabled = value; OnPropertyChanged(); } } }

    private bool _requireDeviceControlEnabled;
    public bool RequireDeviceControlEnabled { get => _requireDeviceControlEnabled; set { if (_requireDeviceControlEnabled != value) { _requireDeviceControlEnabled = value; OnPropertyChanged(); } } }

    private bool _requireSmartAppControlOn;
    public bool RequireSmartAppControlOn { get => _requireSmartAppControlOn; set { if (_requireSmartAppControlOn != value) { _requireSmartAppControlOn = value; OnPropertyChanged(); } } }

    private bool _requireSignaturesUpToDate;
    public bool RequireSignaturesUpToDate { get => _requireSignaturesUpToDate; set { if (_requireSignaturesUpToDate != value) { _requireSignaturesUpToDate = value; OnPropertyChanged(); } } }

    private int _maxFullScanAgeDays;
    public int MaxFullScanAgeDays { get => _maxFullScanAgeDays; set { if (_maxFullScanAgeDays != value) { _maxFullScanAgeDays = value; OnPropertyChanged(); } } }

    private int _maxQuickScanAgeDays;
    public int MaxQuickScanAgeDays { get => _maxQuickScanAgeDays; set { if (_maxQuickScanAgeDays != value) { _maxQuickScanAgeDays = value; OnPropertyChanged(); } } }

    private int _maxAntivirusSignatureAgeHours;
    public int MaxAntivirusSignatureAgeHours { get => _maxAntivirusSignatureAgeHours; set { if (_maxAntivirusSignatureAgeHours != value) { _maxAntivirusSignatureAgeHours = value; OnPropertyChanged(); } } }

    private int _maxAntispywareSignatureAgeHours;
    public int MaxAntispywareSignatureAgeHours { get => _maxAntispywareSignatureAgeHours; set { if (_maxAntispywareSignatureAgeHours != value) { _maxAntispywareSignatureAgeHours = value; OnPropertyChanged(); } } }

    public List<string>? DeviceControlGroupIds { get => _deviceControlGroupIds; set { if (_deviceControlGroupIds != value) { _deviceControlGroupIds = value; OnPropertyChanged(); } } }
    private List<string>? _deviceControlGroupIds;

    public List<string>? DeviceControlRuleIds { get => _deviceControlRuleIds; set { if (_deviceControlRuleIds != value) { _deviceControlRuleIds = value; OnPropertyChanged(); } } }
    private List<string>? _deviceControlRuleIds;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}