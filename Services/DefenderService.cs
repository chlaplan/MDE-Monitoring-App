using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json;

namespace MDE_Monitoring_App
{
    public static class DefenderService
    {
        // Get live Defender status via powershell.exe
        public static DefenderStatus GetLiveStatus()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"Get-MpComputerStatus | ConvertTo-Json -Compress\"",
                    RedirectStandardOutput = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var ps = Process.Start(psi))
                {
                    string output = ps.StandardOutput.ReadToEnd();
                    ps.WaitForExit();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        var dict = JsonSerializer.Deserialize<Dictionary<string, object>>(output);

                        if (dict != null)
                        {
                            return new DefenderStatus
                            {
                                AMProductVersion = dict.GetValueOrDefault("AMProductVersion")?.ToString(),
                                AMEngineVersion = dict.GetValueOrDefault("AMEngineVersion")?.ToString(),
                                AMRunningMode = dict.GetValueOrDefault("AMRunningMode")?.ToString(),
                                RealTimeProtection = (dict.GetValueOrDefault("RealTimeProtectionEnabled")?.ToString() == "True") ? "On" : "Off",
                                AntivirusSignatureAge = dict.GetValueOrDefault("AntivirusSignatureAge")?.ToString(),
                                AntispywareSignatureAge = dict.GetValueOrDefault("AntispywareSignatureAge")?.ToString(),
                                DeviceControlDefaultEnforcement = dict.GetValueOrDefault("DeviceControlDefaultEnforcement")?.ToString(),
                                DeviceControlState = dict.GetValueOrDefault("DeviceControlState")?.ToString()
                            };
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DefenderService error: {ex.Message}");
            }

            return new DefenderStatus();
        }

        // Read recent Windows Defender events
        public static List<LogEntry> GetRecentMDEEvents(int maxEvents = 50)
        {
            var logs = new List<LogEntry>();
            try
            {
                string query = "*[System/Level<=3]"; // Critical, Error, Warning
                var eventQuery = new EventLogQuery(@"Microsoft-Windows-Windows Defender/Operational",
                    PathType.LogName, query);

                using (var logReader = new EventLogReader(eventQuery))
                {
                    EventRecord eventRecord;
                    int count = 0;

                    while ((eventRecord = logReader.ReadEvent()) != null && count < maxEvents)
                    {
                        string normalizedLevel = eventRecord.LevelDisplayName switch
                        {
                            "Information" => "Info",
                            "Warning" => "Warning",
                            "Error" => "Error",
                            "Critical" => "Critical",
                            _ => "Info"
                        };

                        logs.Add(new LogEntry
                        {
                            Time = eventRecord.TimeCreated ?? DateTime.Now,
                            Level = normalizedLevel,
                            Message = eventRecord.FormatDescription() ?? ""
                        });

                        count++;
                    }
                }
            }
            catch (Exception ex)
            {
                logs.Add(new LogEntry
                {
                    Time = DateTime.Now,
                    Level = "Error",
                    Message = $"Failed to read MDE events: {ex.Message}"
                });
            }

            return logs;
        }
    }
}
