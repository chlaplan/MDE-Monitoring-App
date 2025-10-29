using System;
using System.Collections.Generic;
using System.Management;

namespace MDE_Monitoring_App.Services;

public sealed class MpComputerStatusSnapshot
{
    public string AMEngineVersion { get; init; } = "";
    public string AMProductVersion { get; init; } = "";
    public string AMRunningMode { get; init; } = "";
    public bool AMServiceEnabled { get; init; }
    public string AMServiceVersion { get; init; } = "";
    public bool AntispywareEnabled { get; init; }
    public int AntispywareSignatureAge { get; init; }
    public DateTime? AntispywareSignatureLastUpdated { get; init; }
    public string AntispywareSignatureVersion { get; init; } = "";
    public bool AntivirusEnabled { get; init; }
    public int AntivirusSignatureAge { get; init; }
    public DateTime? AntivirusSignatureLastUpdated { get; init; }
    public string AntivirusSignatureVersion { get; init; } = "";
    public bool BehaviorMonitorEnabled { get; init; }
    public bool DefenderSignaturesOutOfDate { get; init; }
    public string DeviceControlDefaultEnforcement { get; init; } = "";
    public DateTime? DeviceControlPoliciesLastUpdated { get; init; }
    public string DeviceControlState { get; init; } = "";
    public int FullScanAge { get; init; }
    public int QuickScanAge { get; init; }
    public bool FullScanOverdue { get; init; }
    public bool QuickScanOverdue { get; init; }
    public bool IoavProtectionEnabled { get; init; }
    public bool IsTamperProtected { get; init; }
    public bool NISEnabled { get; init; }
    public bool OnAccessProtectionEnabled { get; init; }
    public bool RealTimeProtectionEnabled { get; init; }
    public string SmartAppControlState { get; init; } = "";
    public string TDTStatus { get; init; } = "";
    public string TDTMode { get; init; } = "";
    public bool RebootRequired { get; init; }
}

public sealed class MpComputerStatusService
{
    public MpComputerStatusSnapshot GetLocalStatus()
    {
        var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
        scope.Connect();
        var query = new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus");
        using var searcher = new ManagementObjectSearcher(scope, query);
        foreach (ManagementObject mo in searcher.Get())
        {
            return new MpComputerStatusSnapshot
            {
                AMEngineVersion = (string?)mo["AMEngineVersion"] ?? "",
                AMProductVersion = (string?)mo["AMProductVersion"] ?? "",
                AMRunningMode = (string?)mo["AMRunningMode"] ?? "",
                AMServiceEnabled = ToBool(mo["AMServiceEnabled"]),
                AMServiceVersion = (string?)mo["AMServiceVersion"] ?? "",
                AntispywareEnabled = ToBool(mo["AntispywareEnabled"]),
                AntispywareSignatureAge = ToInt(mo["AntispywareSignatureAge"]),
                AntispywareSignatureLastUpdated = ToDate(mo["AntispywareSignatureLastUpdated"]),
                AntispywareSignatureVersion = (string?)mo["AntispywareSignatureVersion"] ?? "",
                AntivirusEnabled = ToBool(mo["AntivirusEnabled"]),
                AntivirusSignatureAge = ToInt(mo["AntivirusSignatureAge"]),
                AntivirusSignatureLastUpdated = ToDate(mo["AntivirusSignatureLastUpdated"]),
                AntivirusSignatureVersion = (string?)mo["AntivirusSignatureVersion"] ?? "",
                BehaviorMonitorEnabled = ToBool(mo["BehaviorMonitorEnabled"]),
                DefenderSignaturesOutOfDate = ToBool(mo["DefenderSignaturesOutOfDate"]),
                DeviceControlDefaultEnforcement = (string?)mo["DeviceControlDefaultEnforcement"] ?? "",
                DeviceControlPoliciesLastUpdated = ToDate(mo["DeviceControlPoliciesLastUpdated"]),
                DeviceControlState = (string?)mo["DeviceControlState"] ?? "",
                FullScanAge = ToInt(mo["FullScanAge"]),
                QuickScanAge = ToInt(mo["QuickScanAge"]),
                FullScanOverdue = ToBool(mo["FullScanOverdue"]),
                QuickScanOverdue = ToBool(mo["QuickScanOverdue"]),
                IoavProtectionEnabled = ToBool(mo["IoavProtectionEnabled"]),
                IsTamperProtected = ToBool(mo["IsTamperProtected"]),
                NISEnabled = ToBool(mo["NISEnabled"]),
                OnAccessProtectionEnabled = ToBool(mo["OnAccessProtectionEnabled"]),
                RealTimeProtectionEnabled = ToBool(mo["RealTimeProtectionEnabled"]),
                SmartAppControlState = (string?)mo["SmartAppControlState"] ?? "",
                TDTStatus = (string?)mo["TDTStatus"] ?? "",
                TDTMode = (string?)mo["TDTMode"] ?? "",
                RebootRequired = ToBool(mo["RebootRequired"])
            };
        }
        return new MpComputerStatusSnapshot();
    }

    private static bool ToBool(object? o) => o is bool b ? b : (o?.ToString() == "True");
    private static int ToInt(object? o) => int.TryParse(o?.ToString(), out var v) ? v : 0;
    private static DateTime? ToDate(object? o)
    {
        if (o == null) return null;
        if (DateTime.TryParse(o.ToString(), out var dt)) return dt;
        return null;
    }
}