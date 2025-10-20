using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Management;

namespace MDE_Monitoring_App.Services
{
    public sealed class FirewallProfileStatus
    {
        public string Profile { get; init; } = "";
        public bool Enabled { get; init; }
        public string RawPolicy { get; init; } = "";
        public string InboundPolicy { get; init; } = "";
        public string OutboundPolicy { get; init; } = "";
        public string Source { get; init; } = "";
        public string EffectiveInbound { get; init; } = "";
        public string EffectiveOutbound { get; init; } = "";
        public string LogFilePath { get; init; } = "";
        public string Diagnostics { get; init; } = "";
        public override string ToString() => $"{Profile}: {(Enabled ? "On" : "Off")} (In:{EffectiveInbound} / Out:{EffectiveOutbound})";
    }

    public sealed class FirewallStatusService
    {
        public IReadOnlyList<FirewallProfileStatus> GetStatus() =>
            GetStatus(null, TimeSpan.FromSeconds(8), CancellationToken.None);

        public IReadOnlyList<FirewallProfileStatus> GetStatus(string? targetMachine, TimeSpan? timeout, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var t = timeout ?? TimeSpan.FromSeconds(8);
            bool remote = IsRemote(targetMachine);

            // WMI / CIM (DCOM) first (does not require WinRM)
            var wmiProfiles = TryGetViaCim(targetMachine, t, ct, remote ? "Remote (CIM)" : "Local (CIM)");
            if (wmiProfiles.Count > 0)
                return wmiProfiles;

            // Local fallback (netsh / PS) only if not remote
            if (!remote)
            {
                var psJson = RunPowerShell(false, null, t, ct);
                var list = ParsePsJson(psJson, "Local (PS)");
                if (list.Count == 0)
                {
                    var netshText = RunNetsh(ct);
                    var netshList = ParseNetsh(netshText, "Local (netsh)");
                    if (netshList.Count > 0) return netshList;
                    return BuildFailure("Local: CIM + PS + netsh failed", false, null, psJson, netshText);
                }
                return list;
            }

            // Remote fallback (requires WinRM) – optional
            var remotePs = RunPowerShell(true, targetMachine, t, ct);
            var remotePsParsed = ParsePsJson(remotePs, $"Remote ({targetMachine}) PS");
            if (remotePsParsed.Count > 0)
                return remotePsParsed;

            // Final failure
            return BuildFailure("Remote: CIM + PS failed", true, targetMachine, remotePs, null);
        }

        private static bool IsRemote(string? host) =>
            !string.IsNullOrWhiteSpace(host) &&
            !host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
            !host.Equals(".", StringComparison.OrdinalIgnoreCase) &&
            !host.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        // CIM / WMI MSFT_NetFirewallProfile
        private static List<FirewallProfileStatus> TryGetViaCim(string? host, TimeSpan timeout, CancellationToken ct, string sourceLabel)
        {
            var list = new List<FirewallProfileStatus>();
            try
            {
                ct.ThrowIfCancellationRequested();
                var scopePath = string.IsNullOrWhiteSpace(host) ||
                                host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                                host.Equals(".", StringComparison.OrdinalIgnoreCase)
                    ? @"root\StandardCimv2"
                    : $@"\\{host}\root\StandardCimv2";

                var scope = new ManagementScope(scopePath);
                var deadline = DateTime.UtcNow + timeout;
                scope.Connect();

                var query = new ObjectQuery("SELECT InstanceID,Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogFileName FROM MSFT_NetFirewallProfile");
                using var searcher = new ManagementObjectSearcher(scope, query);

                foreach (ManagementObject mo in searcher.Get())
                {
                    if (DateTime.UtcNow > deadline) break;

                    var name = (mo["Name"] as string ?? "").Trim();
                    if (string.IsNullOrEmpty(name)) continue;

                    // Enabled (0/1)
                    bool enabled = false;
                    try { enabled = Convert.ToInt32(mo["Enabled"] ?? 0) != 0; } catch { }

                    int inboundCode = SafeInt(mo["DefaultInboundAction"]);
                    int outboundCode = SafeInt(mo["DefaultOutboundAction"]);
                    string inboundRaw = ActionText(inboundCode, true);
                    string outboundRaw = ActionText(outboundCode, false);

                    string effectiveInbound = Effective(inboundRaw, true);
                    string effectiveOutbound = Effective(outboundRaw, false);

                    string logPathRaw = (mo["LogFileName"] as string ?? "").Trim();
                    string expandedLog = ExpandLogPath(logPathRaw, scopePath);

                    list.Add(new FirewallProfileStatus
                    {
                        Profile = name,
                        Enabled = enabled,
                        RawPolicy = inboundRaw + "," + outboundRaw,
                        InboundPolicy = inboundRaw,
                        OutboundPolicy = outboundRaw,
                        EffectiveInbound = effectiveInbound,
                        EffectiveOutbound = effectiveOutbound,
                        LogFilePath = expandedLog,
                        Source = sourceLabel,
                        Diagnostics = $"InboundCode={inboundCode};OutboundCode={outboundCode};LogRaw={logPathRaw}"
                    });
                }
            }
            catch (Exception ex)
            {
                if (list.Count == 0)
                {
                    list.Add(new FirewallProfileStatus
                    {
                        Profile = "CIM-Failure",
                        Enabled = false,
                        RawPolicy = "",
                        InboundPolicy = "Error",
                        OutboundPolicy = "Error",
                        EffectiveInbound = "Unknown",
                        EffectiveOutbound = "Unknown",
                        Source = sourceLabel,
                        Diagnostics = ex.GetType().Name + ": " + ex.Message
                    });
                }
            }
            return list;
        }

        private static int SafeInt(object? v)
        {
            try { return Convert.ToInt32(v); } catch { return -1; }
        }

        // Map numeric action codes (observed sample: 4=Block inbound, 0=Allow outbound, others -> NotConfigured)
        private static string ActionText(int code, bool inbound)
        {
            return code switch
            {
                0 => "Allow",
                4 => "Block",
                -1 => "Unknown",
                _ => "NotConfigured"
            };
        }

        private static string ExpandLogPath(string raw, string scopePath)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            var localSystemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            if (raw.IndexOf("%systemroot%", StringComparison.OrdinalIgnoreCase) >= 0)
                raw = raw.Replace("%systemroot%", localSystemRoot, StringComparison.OrdinalIgnoreCase);
            try { return System.IO.Path.GetFullPath(raw); } catch { return raw; }
        }

        private static string Effective(string raw, bool inbound) =>
            string.IsNullOrWhiteSpace(raw) || raw.Equals("NotConfigured", StringComparison.OrdinalIgnoreCase)
                ? (inbound ? "Block (Default)" : "Allow (Default)")
                : raw;

        // Existing PS / netsh helpers retained for non-CIM fallback
        private static string RunPowerShell(bool remote, string? host, TimeSpan timeout, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            string inner = @"
Import-Module NetSecurity -ErrorAction SilentlyContinue;
try {
  $p = Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction;
  if (-not $p) { '{}' } else { $p | ConvertTo-Json -Depth 2 -Compress }
} catch { '{}' }";
            string script = remote
                ? $"Invoke-Command -ComputerName '{Escape(host!)}' -ScriptBlock {{ {inner} }}"
                : inner;
            return RunPsRaw(script, timeout, ct);
        }

        private static string RunPsRaw(string script, TimeSpan timeout, CancellationToken ct)
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command " + QuoteForCmd(script))
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            using var proc = Process.Start(psi);
            if (proc == null) return "";
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
            {
                try { proc.Kill(); } catch { }
                return "TIMEOUT";
            }
            ct.ThrowIfCancellationRequested();
            var outText = stdoutTask.Result.Trim();
            var err = stderrTask.Result.Trim();
            if (!string.IsNullOrEmpty(err))
                outText += "\n#ERR:" + err;
            return outText;
        }

        private static string RunNetsh(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var psi = new ProcessStartInfo("netsh", "advfirewall show allprofiles")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p == null) return "";
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(4000);
            return text;
        }

        private static List<FirewallProfileStatus> ParsePsJson(string json, string sourceLabel)
        {
            var list = new List<FirewallProfileStatus>();
            if (string.IsNullOrWhiteSpace(json) || json == "{}") return list;
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object)
                    TryAddPs(root, list, sourceLabel);
                else if (root.ValueKind == JsonValueKind.Array)
                    foreach (var el in root.EnumerateArray())
                        TryAddPs(el, list, sourceLabel);
            }
            catch { }
            return list;
        }

        private static void TryAddPs(JsonElement el, List<FirewallProfileStatus> list, string source)
        {
            if (el.ValueKind != JsonValueKind.Object) return;
            var name = el.TryGetProperty("Name", out var pName) ? pName.GetString() ?? "" : "";
            if (string.IsNullOrWhiteSpace(name)) return;
            bool enabled = false;
            if (el.TryGetProperty("Enabled", out var pEnabled))
            {
                enabled = pEnabled.ValueKind switch
                {
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Number => pEnabled.GetInt32() != 0,
                    JsonValueKind.String => bool.TryParse(pEnabled.GetString(), out var b) && b,
                    _ => false
                };
            }
            string inboundRaw = el.TryGetProperty("DefaultInboundAction", out var pIn) ? pIn.GetString() ?? "" : "";
            string outboundRaw = el.TryGetProperty("DefaultOutboundAction", out var pOut) ? pOut.GetString() ?? "" : "";
            list.Add(new FirewallProfileStatus
            {
                Profile = name,
                Enabled = enabled,
                RawPolicy = inboundRaw + "," + outboundRaw,
                InboundPolicy = inboundRaw,
                OutboundPolicy = outboundRaw,
                EffectiveInbound = Effective(inboundRaw, true),
                EffectiveOutbound = Effective(outboundRaw, false),
                Source = source,
                Diagnostics = "PS"
            });
        }

        private static List<FirewallProfileStatus> ParseNetsh(string text, string sourceLabel)
        {
            var list = new List<FirewallProfileStatus>();
            if (string.IsNullOrWhiteSpace(text)) return list;
            var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            string current = "";
            bool enabled = false;
            string inbound = "";
            string outbound = "";
            string rawPolicy = "";
            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();
                var idx = line.IndexOf("Profile Settings:", StringComparison.OrdinalIgnoreCase);
                if (idx > 0)
                {
                    Commit();
                    current = line.Substring(0, idx).Trim();
                    continue;
                }
                if (current.Length == 0) continue;
                if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                    enabled = line.IndexOf("ON", StringComparison.OrdinalIgnoreCase) >= 0;
                else if (line.StartsWith("Firewall Policy", StringComparison.OrdinalIgnoreCase))
                {
                    var last = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)[^1];
                    rawPolicy = last;
                    var pieces = last.Split(',');
                    if (pieces.Length == 2)
                    {
                        inbound = RemoveSuffix(pieces[0], "Inbound");
                        outbound = RemoveSuffix(pieces[1], "Outbound");
                    }
                }
            }
            Commit();
            return list;

            void Commit()
            {
                if (string.IsNullOrEmpty(current)) return;
                list.Add(new FirewallProfileStatus
                {
                    Profile = current,
                    Enabled = enabled,
                    RawPolicy = rawPolicy,
                    InboundPolicy = inbound,
                    OutboundPolicy = outbound,
                    EffectiveInbound = string.IsNullOrWhiteSpace(inbound) ? "Block (Default)" : inbound,
                    EffectiveOutbound = string.IsNullOrWhiteSpace(outbound) ? "Allow (Default)" : outbound,
                    Source = sourceLabel,
                    Diagnostics = "netsh"
                });
                current = "";
                inbound = outbound = rawPolicy = "";
                enabled = false;
            }
        }

        private static string RemoveSuffix(string value, string suffix) =>
            value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                ? value.Substring(0, value.Length - suffix.Length)
                : value;

        private static List<FirewallProfileStatus> BuildFailure(string reason, bool remote, string? host, string? extra1, string? extra2) =>
            new()
            {
                new FirewallProfileStatus
                {
                    Profile = remote ? $"Remote({host})" : "Local",
                    Enabled = false,
                    RawPolicy = "",
                    InboundPolicy = "Error",
                    OutboundPolicy = "Error",
                    EffectiveInbound = "Unknown",
                    EffectiveOutbound = "Unknown",
                    Source = reason,
                    Diagnostics = Truncate($"{extra1}\n---\n{extra2}", 700)
                }
            };

        private static string Truncate(string v, int max) =>
            string.IsNullOrEmpty(v) || v.Length <= max ? v : v.Substring(0, max - 1) + "…";

        private static string Escape(string s) => s.Replace("'", "''");
        private static string QuoteForCmd(string s) => "\"" + s.Replace("\"", "`\"") + "\"";
    }
}