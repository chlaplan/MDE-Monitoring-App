using System;
using System.Diagnostics;
using System.Globalization;

namespace MDE_Monitoring_App.Services
{
    public class IntuneSyncService
    {
        // Parses "dsregcmd /status" output for "Last Device Sync Time"
        public DateTime? GetLastSync()
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
                if (proc == null) return null;
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                // Look for a line like: "Last Device Sync Time : 2024-08-31 15:22:10.000 UTC"
                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.Contains("Last Device Sync Time", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':', 2);
                        if (parts.Length == 2)
                        {
                            var raw = parts[1].Trim();
                            // Remove trailing timezone text if present
                            raw = raw.Replace("UTC", "", StringComparison.OrdinalIgnoreCase).Trim();
                            if (DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
                                return dt.ToUniversalTime();
                        }
                    }
                }
            }
            catch { }
            return null;
        }
    }
}